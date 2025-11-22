// server.js - FIXED TO MATCH DATABASE SCHEMA
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_this';

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'project_repo',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Initialize DB: seed admin/guide/student if not exists
async function initDB() {
  const conn = await pool.getConnection();
  try {
    // Seed departments
    await conn.query(`INSERT IGNORE INTO departments (department_id, name) VALUES (1, 'CSE'), (2, 'IT'), (3, 'ECE'), (4, 'Mech'), (5, 'Civil')`);

    // Seed admin (username: admin@123 password: admin123)
    const [admins] = await conn.query(`SELECT * FROM admins WHERE username = ?`, ['admin@123']);
    if (admins.length === 0) {
      await conn.query(`INSERT INTO admins (username, password) VALUES (?, ?)`, ['admin@123', 'admin123']);
      console.log('Seeded admin -> username: admin@123 / password: admin123');
    }

    // Seed guide (Guide One / guidepass)
    const [grows] = await conn.query(`SELECT * FROM guides WHERE guide_name = ?`, ['Guide One']);
    if (grows.length === 0) {
      await conn.query(`INSERT INTO guides (guide_name, department_id, designation, password) VALUES (?, ?, ?, ?)`,
        ['Guide One', 1, 'Asst. Prof', 'guidepass']);
      console.log('Seeded guide -> guide_name: Guide One / password: guidepass');
    }

    // Seed student (roll: S1001 / studentpass)
    const [srows] = await conn.query(`SELECT * FROM students WHERE roll_number = ?`, ['S1001']);
    if (srows.length === 0) {
      await conn.query(`INSERT INTO students (roll_number, name, department_id, batch, password) VALUES (?, ?, ?, ?, ?)`,
        ['S1001', 'Student One', 1, '2023', 'studentpass']);
      console.log('Seeded student -> roll: S1001 / password: studentpass');
    }

    // Seed a sample project
    const [guide] = await conn.query(`SELECT * FROM guides WHERE guide_name = ?`, ['Guide One']);
    if (guide.length) {
      const guideId = guide[0].guide_id;
      const [projects] = await conn.query(`SELECT * FROM projects WHERE title = ?`, ['Sample Project']);
      if (projects.length === 0) {
        const [res] = await conn.query(`INSERT INTO projects (title, description, guide_id, department_id, member_type, project_type) VALUES (?, ?, ?, ?, ?, ?)`,
          ['Sample Project', 'A sample seeded project', guideId, 1, 'individual', 'semester']);
        const projectId = res.insertId;

        const [student] = await conn.query(`SELECT * FROM students WHERE roll_number = ?`, ['S1001']);
        if (student.length) {
          await conn.query(`INSERT IGNORE INTO project_students (project_id, student_id) VALUES (?, ?)`, [projectId, student[0].student_id]);
          console.log('Seeded Sample Project and mapped Student One to it.');
        }
      }
    }

    console.log('DB initialized');
  } catch (err) {
    console.error('DB init error', err);
  } finally {
    conn.release();
  }
}

// Middleware: authenticate token
function authMiddleware(requiredRoles = []) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Malformed token' });

    try {
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload;
      if (requiredRoles.length && !requiredRoles.includes(payload.role)) {
        return res.status(403).json({ message: 'Forbidden - insufficient role' });
      }
      next();
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token', error: err.message });
    }
  };
}

// AUTH route - unified login
app.post('/auth/login', async (req, res) => {
  const { role, usernameOrRoll, password } = req.body;
  if (!role || !usernameOrRoll || !password) return res.status(400).json({ message: 'role, usernameOrRoll and password required' });

  try {
    const conn = await pool.getConnection();
    let row;
    
    if (role === 'admin') {
      const [r] = await conn.query(`SELECT * FROM admins WHERE username = ?`, [usernameOrRoll]);
      row = r[0];
      if (!row || password !== row.password) {
        conn.release();
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const token = jwt.sign({ id: row.admin_id, role: 'admin', username: row.username }, JWT_SECRET, { expiresIn: '8h' });
      conn.release();
      return res.json({ token, role: 'admin' });
      
    } else if (role === 'guide') {
      const [r] = await conn.query(`SELECT * FROM guides WHERE guide_name = ?`, [usernameOrRoll]);
      row = r[0];
      if (!row || password !== row.password) {
        conn.release();
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const token = jwt.sign({ id: row.guide_id, role: 'guide', name: row.guide_name }, JWT_SECRET, { expiresIn: '8h' });
      conn.release();
      return res.json({ token, role: 'guide' });
      
    } else if (role === 'student') {
      const [r] = await conn.query(`SELECT * FROM students WHERE roll_number = ?`, [usernameOrRoll]);
      row = r[0];
      if (!row || password !== row.password) {
        conn.release();
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      const token = jwt.sign({ id: row.student_id, role: 'student', roll_number: row.roll_number }, JWT_SECRET, { expiresIn: '8h' });
      conn.release();
      return res.json({ token, role: 'student' });
      
    } else {
      conn.release();
      return res.status(400).json({ message: 'Invalid role' });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

//
// STUDENT routes
//
app.get('/students/me/project', authMiddleware(['student']), async (req, res) => {
  try {
    const studentId = req.user.id;
    const conn = await pool.getConnection();
    const [rows] = await conn.query(`
      SELECT p.*, g.guide_name, d.name as department_name
      FROM projects p
      JOIN project_students ps ON ps.project_id = p.project_id
      LEFT JOIN guides g ON g.guide_id = p.guide_id
      LEFT JOIN departments d ON d.department_id = p.department_id
      WHERE ps.student_id = ?
    `, [studentId]);

    for (const p of rows) {
      if (p.project_type === 'final_year') {
        const [intern] = await conn.query(`SELECT * FROM internships WHERE project_id = ? AND student_id = ?`, [p.project_id, studentId]);
        p.internship = intern[0] || null;
      }
      const [members] = await conn.query(`
        SELECT s.student_id, s.roll_number, s.name, d.name as department_name
        FROM students s 
        JOIN project_students ps ON ps.student_id = s.student_id
        LEFT JOIN departments d ON d.department_id = s.department_id
        WHERE ps.project_id = ?
      `, [p.project_id]);
      p.team_members = members;
    }
    conn.release();
    return res.json({ projects: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

//
// GUIDE routes
//
app.post('/guides/projects', authMiddleware(['guide']), async (req, res) => {
  const guideId = req.user.id;
  const { title, description, department_id, member_type = 'individual', project_type = 'semester' } = req.body;
  if (!title) return res.status(400).json({ message: 'title required' });
  
  try {
    const conn = await pool.getConnection();
    const [r] = await conn.query(`INSERT INTO projects (title, description, guide_id, department_id, member_type, project_type) VALUES (?, ?, ?, ?, ?, ?)`,
      [title, description, guideId, department_id, member_type, project_type]);
    conn.release();
    return res.json({ message: 'Project created', project_id: r.insertId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.post('/guides/projects/:projectId/add-student', authMiddleware(['guide']), async (req, res) => {
  const guideId = req.user.id;
  const projectId = req.params.projectId;
  const { studentRoll } = req.body;
  if (!studentRoll) return res.status(400).json({ message: 'studentRoll required' });

  try {
    const conn = await pool.getConnection();
    const [proj] = await conn.query(`SELECT * FROM projects WHERE project_id = ? AND guide_id = ?`, [projectId, guideId]);
    if (!proj.length) {
      conn.release();
      return res.status(403).json({ message: 'Project not found or not owned by you' });
    }

    const [s] = await conn.query(`SELECT * FROM students WHERE roll_number = ?`, [studentRoll]);
    if (!s.length) {
      conn.release();
      return res.status(404).json({ message: 'Student not found' });
    }
    const studentId = s[0].student_id;

    if (proj[0].member_type === 'individual') {
      const [existing] = await conn.query(`SELECT * FROM project_students WHERE project_id = ?`, [projectId]);
      if (existing.length) {
        conn.release();
        return res.status(400).json({ message: 'This project is individual and already has a mapped student' });
      }
    }

    await conn.query(`INSERT IGNORE INTO project_students (project_id, student_id) VALUES (?, ?)`, [projectId, studentId]);
    conn.release();
    return res.json({ message: 'Student mapped to project' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.post('/guides/projects/:projectId/internship', authMiddleware(['guide']), async (req, res) => {
  const guideId = req.user.id;
  const projectId = req.params.projectId;
  const { studentRoll, company_name, duration, domain } = req.body;
  if (!studentRoll || !company_name) return res.status(400).json({ message: 'studentRoll and company_name required' });

  try {
    const conn = await pool.getConnection();
    const [proj] = await conn.query(`SELECT * FROM projects WHERE project_id = ? AND guide_id = ?`, [projectId, guideId]);
    if (!proj.length) {
      conn.release();
      return res.status(403).json({ message: 'Project not found or not owned by you' });
    }
    if (proj[0].project_type !== 'final_year') {
      conn.release();
      return res.status(400).json({ message: 'Internship details only allowed for final_year projects' });
    }

    const [s] = await conn.query(`SELECT * FROM students WHERE roll_number = ?`, [studentRoll]);
    if (!s.length) {
      conn.release();
      return res.status(404).json({ message: 'Student not found' });
    }
    const studentId = s[0].student_id;

    await conn.query(`
      INSERT INTO internships (project_id, student_id, company_name, duration, domain)
      VALUES (?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE company_name = VALUES(company_name), duration = VALUES(duration), domain = VALUES(domain)
    `, [projectId, studentId, company_name, duration, domain]);

    conn.release();
    return res.json({ message: 'Internship updated for student' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/guides/me/projects', authMiddleware(['guide']), async (req, res) => {
  try {
    const guideId = req.user.id;
    const conn = await pool.getConnection();
    const [projects] = await conn.query(`
      SELECT p.*, d.name as department_name 
      FROM projects p
      LEFT JOIN departments d ON d.department_id = p.department_id
      WHERE p.guide_id = ?
    `, [guideId]);

    for (const p of projects) {
      const [members] = await conn.query(`
        SELECT s.student_id, s.roll_number, s.name, d.name as department_name
        FROM students s 
        JOIN project_students ps ON ps.student_id = s.student_id
        LEFT JOIN departments d ON d.department_id = s.department_id
        WHERE ps.project_id = ?
      `, [p.project_id]);
      p.team_members = members;
    }

    conn.release();
    return res.json({ projects });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

//
// ADMIN routes
//
app.get('/admin/dashboard', authMiddleware(['admin']), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [[{ total_departments }]] = await conn.query(`SELECT COUNT(*) AS total_departments FROM departments`);
    const [[{ total_students }]] = await conn.query(`SELECT COUNT(*) AS total_students FROM students`);
    const [[{ total_guides }]] = await conn.query(`SELECT COUNT(*) AS total_guides FROM guides`);
    const [[{ total_projects }]] = await conn.query(`SELECT COUNT(*) AS total_projects FROM projects`);

    const [finalProjects] = await conn.query(`
      SELECT p.project_id, p.title, p.project_type, g.guide_name, d.name as department_name
      FROM projects p 
      LEFT JOIN guides g ON p.guide_id = g.guide_id
      LEFT JOIN departments d ON d.department_id = p.department_id
      WHERE p.project_type = 'final_year'
    `);

    for (const p of finalProjects) {
      const [members] = await conn.query(`
        SELECT s.student_id, s.roll_number, s.name
        FROM students s 
        JOIN project_students ps ON ps.student_id = s.student_id 
        WHERE ps.project_id = ?
      `, [p.project_id]);
      p.team_members = members;
    }

    conn.release();
    return res.json({
      totals: { total_departments, total_students, total_guides, total_projects },
      final_year_projects: finalProjects
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/admin/students', authMiddleware(['admin']), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query(`
      SELECT s.student_id, s.roll_number, s.name, d.name as department_name, s.batch 
      FROM students s
      LEFT JOIN departments d ON d.department_id = s.department_id
    `);
    conn.release();
    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/admin/guides', authMiddleware(['admin']), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query(`
      SELECT g.guide_id, g.guide_name, d.name as department_name, g.designation 
      FROM guides g
      LEFT JOIN departments d ON d.department_id = g.department_id
    `);
    conn.release();
    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/admin/projects', authMiddleware(['admin']), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query(`
      SELECT p.*, g.guide_name, d.name as department_name 
      FROM projects p 
      LEFT JOIN guides g ON p.guide_id = g.guide_id
      LEFT JOIN departments d ON d.department_id = p.department_id
    `);
    
    for (const p of rows) {
      const [members] = await conn.query(`
        SELECT s.student_id, s.roll_number, s.name 
        FROM students s 
        JOIN project_students ps ON ps.student_id = s.student_id 
        WHERE ps.project_id = ?
      `, [p.project_id]);
      p.team_members = members;
    }
    conn.release();
    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/admin/departments', authMiddleware(['admin']), async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query(`SELECT * FROM departments`);
    conn.release();
    return res.json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.send('Student Project Repository API. Use /auth/login to authenticate.');
});

(async () => {
  try {
    await initDB();
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log('Login credentials:');
      console.log('Admin -> role: admin, usernameOrRoll: admin@123, password: admin123');
      console.log('Guide -> role: guide, usernameOrRoll: Guide One, password: guidepass');
      console.log('Student -> role: student, usernameOrRoll: S1001, password: studentpass');
    });
  } catch (err) {
    console.error('Startup error', err);
    process.exit(1);
  }
})();