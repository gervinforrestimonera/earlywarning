/**
 * BINHS Early Warning System - Backend Server
 * Technology Stack: Node.js, Express.js, MySQL (mysql2), JavaScript Decision Tree
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const db = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// JavaScript Decision Tree Predictor (replaces Python subprocess)
const { predictStudent, predictAllStudents, predictStudentQ1, predictAllStudentsQ1, getModelMetadata, ruleBasedRisk, getQ1ModelMetadata } = require('./ml/predictor');

// Authoritative grade calculation module (official school grading system)
const GradeCalc = require('./js/grade-calc');

function normalizeTerm(value) {
  const m = String(value || '').match(/(\d+)/);
  const n = m ? m[1] : '';
  if (n === '1' || n === '2' || n === '3' || n === '4') return 'Term ' + n;
  return value;
}

function termAliases(term) {
  const m = String(term || 'Term 1').match(/(\d+)/);
  const n = m ? m[1] : '1';
  if (n === '1') return ['Term 1', 'Q1', 'Quarter 1', 'Quarter1'];
  if (n === '2') return ['Term 2', 'Q2', 'Quarter 2', 'Quarter2'];
  if (n === '3') return ['Term 3', 'Q3', 'Quarter 3', 'Quarter3'];
  if (n === '4') return ['Term 4', 'Q4', 'Quarter 4', 'Quarter4'];
  return [String(term)];
}

// Load Q1 Decision Tree model metadata
let q1ModelMetadata = null;
try {
  q1ModelMetadata = getQ1ModelMetadata();
} catch (err) {
  console.error('[Q1 Decision Tree] Failed to load model metadata:', err.message);
}
const app = express();
const PORT = process.env.PORT || 5000;

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '8h';

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET must be set in .env before starting the server.');
}

const configuredOrigins = (process.env.CORS_ORIGINS || 'http://localhost:5000,http://127.0.0.1:5000')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

const blockedStaticFiles = new Set([
  'server.js', 'db.js', 'database.sql', 'k.sql', 'package.json', 'package-lock.json',
  'test_system.js', '_e2e_test.js', 'students_seed_backup.js', 'student_information.csv',
  'server.log', '.env']);
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 10;

function loginRateLimit(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const record = loginAttempts.get(key);
  const now = Date.now();
  if (record && now - record.firstAttempt < LOGIN_WINDOW_MS && record.count >= MAX_LOGIN_ATTEMPTS) {
    return res.status(429).json({ success: false, message: 'Too many login attempts. Try again in 15 minutes.' });
  }
  if (record && now - record.firstAttempt >= LOGIN_WINDOW_MS) loginAttempts.delete(key);
  req.loginRateLimitKey = key;
  next();
}

function recordFailedLogin(req) {
  const key = req.loginRateLimitKey || req.ip || 'unknown';
  const now = Date.now();
  const record = loginAttempts.get(key);
  if (!record || now - record.firstAttempt >= LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstAttempt: now });
  } else {
    record.count += 1;
  }
}

// Middleware
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});
app.use(cors({
  origin(origin, callback) {
    // Requests from the locally-opened development UI have no Origin header.
    if (!origin || configuredOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS policy.'));
  }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
app.use((req, res, next) => {
  const requestedPath = decodeURIComponent(req.path).replace(/^\/+/, '');
  const firstPathSegment = requestedPath.split('/')[0];
  if (blockedStaticFiles.has(requestedPath) || requestedPath.startsWith('js/_archive/') || ['node_modules', 'ml', '.git', '.env'].includes(firstPathSegment)) {
    return res.status(404).end();
  }
  next();
});
app.use(express.static(__dirname, { dotfiles: 'deny', index: 'index.html' }));

// ============================================================================
// ML HELPER: JavaScript Decision Tree Prediction (replaces Python subprocess)
// ============================================================================
/**
 * Run ML prediction using the JavaScript Decision Tree predictor.
 * Mirrors the output format of the original Python predict.py.
 *
 * @param {string[]} args - CLI-style arguments (--all, --lrn <value>, --features <csv>)
 * @returns {Promise<object>} Same JSON structure as predict.py output
 */
async function runJavascriptML(args = []) {
  try {
    if (args.includes('--features')) {
      const featuresIndex = args.indexOf('--features');
      const featureStr = args[featuresIndex + 1];
      const parts = featureStr.split(',').map(parseFloat);
      if (parts.length < 5) {
        throw new Error('Expected 5 features: q1,q2,q3,absences,attendanceRate');
      }
      const [q1, q2, q3, absences, attendanceRate] = parts;
      const result = predictStudent({ q1, q2, q3, absences, attendanceRate });
      return { success: true, prediction: result };
    }

    return { success: false, error: 'Unknown ML arguments' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// ============================================================================
// 1. AUTHENTICATION ROUTES
// ============================================================================

// POST /api/auth/login
app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password) {
    recordFailedLogin(req);
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    const [rows] = await db.query(
      'SELECT user_id, name, username, password, role, role_title, section, status FROM users WHERE username = ?',
      [username.trim()]
    );

    if (rows.length === 0) {
      recordFailedLogin(req);
      await logSystemEvent('Guest', 'Unknown', `Failed login attempt for user: ${username}`, 'Authentication', 'warning', req.ip);
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    const user = rows[0];

    // Password verification: support bcrypt hashes and lazy migration from plaintext
    let passwordValid = false;
    try {
      // Only use bcrypt.compare if the stored password looks like a bcrypt hash
      if (user.password.startsWith('$2a$') || user.password.startsWith('$2b$') || user.password.startsWith('$2y$')) {
        passwordValid = await bcrypt.compare(password, user.password);
      } else {
        // Plaintext password - direct comparison
        passwordValid = (user.password === password);
      }
    } catch (bcryptErr) {
      passwordValid = false;
    }

    if (!passwordValid) {
      recordFailedLogin(req);
      await logSystemEvent(user.name, user.role, `Failed login attempt (wrong password) for: ${username}`, 'Authentication', 'warning', req.ip);
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    // Lazy migration: if password was stored in plaintext, hash it now
    if (!user.password.startsWith('$2a$') && !user.password.startsWith('$2b$') && !user.password.startsWith('$2y$')) {
      try {
        const hashed = await bcrypt.hash(password, 10);
        await db.query('UPDATE users SET password = ? WHERE user_id = ?', [hashed, user.user_id]);
      } catch (hashErr) {
        console.warn('[Login] Password rehash failed:', hashErr.message);
      }
    }

    if (user.status !== 'Active') {
      recordFailedLogin(req);
      return res.status(403).json({ success: false, message: 'Account is deactivated. Contact Administrator.' });
    }

    // Fetch all sections assigned to this teacher (multi-section support)
    let teacherSections = [];
    try {
      const [sectionRows] = await db.query(
        'SELECT section FROM teacher_sections WHERE teacher_id = ? ORDER BY section',
        [user.user_id]
      );
      teacherSections = sectionRows.map(r => r.section);
    } catch (sectionErr) {
      console.error('[Login] Could not load teacher section assignments:', sectionErr.message);
      teacherSections = [];
    }

    // Record login audit log
    await logSystemEvent(user.name, user.role, `User logged in successfully`, 'Authentication', 'success', req.ip);
    loginAttempts.delete(req.loginRateLimitKey);

    // Issue JWT
    const token = jwt.sign(
      { userId: user.user_id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Exclude password from response
    delete user.password;
    res.json({
      success: true,
      token,
      user: {
        userId: user.user_id,
        name: user.name,
        username: user.username,
        role: user.role,
        roleTitle: user.role_title,
        section: teacherSections[0] || '',
        sections: teacherSections
      }
    });
  } catch (err) {
    console.error('[Login Error]:', err);
    res.status(500).json({ success: false, message: 'Database error during authentication.' });
  }
});

// POST /api/auth/register (Admin-only - creates new Teacher accounts)
app.post('/api/auth/register', loginRateLimit, authenticate, requireRole('Admin'), async (req, res) => {
  const { name, username, password, confirmPassword, role = 'Teacher' } = req.body;
  if (![name, username, password].every(value => typeof value === 'string' && value.trim()) || !confirmPassword) {
    return res.status(400).json({ success: false, message: 'Full name, username, and password are required.' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: 'Passwords do not match.' });
  }
  if (password.length < 12) {
    return res.status(400).json({ success: false, message: 'Password must be at least 12 characters.' });
  }
  if (role !== 'Teacher') {
    return res.status(400).json({ success: false, message: 'Invalid role. Only Teacher accounts can be registered.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const roleTitle = role === 'Admin' ? 'System Administrator' : 'Teacher / Advisor';
    const [result] = await db.query(
      `INSERT INTO users (name, username, password, role, role_title, section, status, date_created)
       VALUES (?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(CURDATE(), '%b %e, %Y'))`,
      [name.trim(), username.trim().toLowerCase(), hash, role, roleTitle, '', 'Active']
    );
    await logSystemEvent(req.user.username, req.user.role, `Admin-created Teacher account: ${username.trim()}`, 'Authentication', 'info', req.ip);
    res.status(201).json({ success: true, userId: result.insertId, username: username.trim().toLowerCase() });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ success: false, message: 'That username is already in use.' });
    console.error('[Register Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to create account.' });
  }
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' || newPassword.length < 12) {
    return res.status(400).json({ success: false, message: 'A new password of at least 12 characters is required.' });
  }

  try {
    const [rows] = await db.query('SELECT password FROM users WHERE user_id = ?', [req.user.id]);
    if (rows.length === 0 || !(await bcrypt.compare(currentPassword, rows[0].password))) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
    }
    const hash = await bcrypt.hash(newPassword, 12);
    await db.query('UPDATE users SET password = ? WHERE user_id = ?', [hash, req.user.id]);
    await logSystemEvent(req.user.username, req.user.role, 'Changed account password', 'Authentication', 'info', req.ip);
    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    console.error('[Change Password Error]:', err);
    res.status(500).json({ success: false, message: 'Unable to change password.' });
  }
});

// GET /api/auth/profile
app.get('/api/auth/profile', authenticate, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT user_id AS userId, name, username, role, role_title AS roleTitle, email, phone FROM users WHERE user_id = ?',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'User profile not found.' });
    res.json({ success: true, profile: rows[0] });
  } catch (err) { res.status(500).json({ success: false, message: 'Could not retrieve profile.' }); }
});

// PUT /api/auth/profile
app.put('/api/auth/profile', authenticate, async (req, res) => {
  const { name, email = '', phone = '', roleTitle = '' } = req.body;
  if (typeof name !== 'string' || !name.trim() || typeof email !== 'string' || typeof phone !== 'string' || typeof roleTitle !== 'string') {
    return res.status(400).json({ success: false, message: 'Invalid profile details.' });
  }
  try {
    await db.query('UPDATE users SET name = ?, email = ?, phone = ?, role_title = ? WHERE user_id = ?', [name.trim(), email.trim(), phone.trim(), roleTitle.trim(), req.user.id]);
    await logSystemEvent(req.user.username, req.user.role, 'Updated profile details', 'User Management', 'info', req.ip);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, message: 'Could not update profile.' }); }
});

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================

/**
 * authenticate: Verifies JWT from Authorization: Bearer <token> header.
 * Populates req.user with { id, username, role } on success.
 */
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Access token required.' });
  }

  const token = authHeader.substring(7); // strip "Bearer "
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      id: decoded.userId,
      username: decoded.username,
      role: decoded.role
    };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
}

/**
 * requireRole: Ensures the authenticated user has one of the allowed roles.
 * Usage: requireRole('Admin') or requireRole('Admin', 'Teacher')
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Authentication required.' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Insufficient privileges.' });
    }
    next();
  };
}

function isAdmin(req) {
  return req.user && req.user.role === 'Admin';
}

async function canAccessStudent(req, student) {
  if (!req.user) return false;
  if (isAdmin(req)) return true;
  if (!student || !student.section) return false;
  const [rows] = await db.query(
    'SELECT 1 FROM teacher_sections WHERE teacher_id = ? AND section = ? LIMIT 1',
    [req.user.id, student.section]
  );
  return rows.length > 0;
}

function validateStudentUpdate(body) {
  const numericFields = ['q1', 'q2', 'q3', 'q4', 'absences', 'attendanceRate'];
  for (const field of numericFields) {
    if (body[field] === undefined || body[field] === null || body[field] === '') continue;
    const value = Number(body[field]);
    const maximum = field === 'absences' ? 365 : 100;
    if (!Number.isFinite(value) || value < 0 || value > maximum) {
      return `${field} must be a number between 0 and ${maximum}.`;
    }
  }
  return null;
}

async function accessibleSections(req) {
  if (!req.user) return [];
  if (isAdmin(req)) return null;
  const [rows] = await db.query(
    'SELECT section FROM teacher_sections WHERE teacher_id = ?',
    [req.user.id]
  );
  return rows.map(r => r.section);
}

// ============================================================================
// USER MANAGEMENT (ADMIN ONLY)
// ============================================================================
app.get('/api/users', authenticate, requireRole('Admin'), async (req, res) => {
  try {
    const [users] = await db.query(
      `SELECT user_id AS userId, name, username, role, role_title AS roleTitle,
              status, date_created AS dateCreated
       FROM users ORDER BY name ASC`
    );
    const [sectionRows] = await db.query(
      'SELECT teacher_id AS teacherId, section FROM teacher_sections ORDER BY section'
    );
    const sectionsByTeacher = new Map();
    sectionRows.forEach(row => {
      if (!sectionsByTeacher.has(row.teacherId)) sectionsByTeacher.set(row.teacherId, []);
      sectionsByTeacher.get(row.teacherId).push(row.section);
    });
    res.json({
      success: true,
      users: users.map(user => ({ ...user, sections: sectionsByTeacher.get(user.userId) || [] }))
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve users.' });
  }
});

app.post('/api/users', authenticate, requireRole('Admin'), async (req, res) => {
  const { name, username, password, role = 'Teacher', status = 'Active' } = req.body;
  if (![name, username, password].every(value => typeof value === 'string' && value.trim()) || password.length < 12) {
    return res.status(400).json({ success: false, message: 'Name, username, and a 12-character password are required.' });
  }
  if (!['Admin', 'Teacher'].includes(role) || !['Active', 'Inactive'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid role or account status.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const roleTitle = role === 'Admin' ? 'System Administrator' : 'Teacher / Advisor';
    const [result] = await db.query(
      `INSERT INTO users (name, username, password, role, role_title, section, status, date_created)
       VALUES (?, ?, ?, ?, ?, ?, ?, DATE_FORMAT(CURDATE(), '%b %e, %Y'))`,
      [name.trim(), username.trim().toLowerCase(), hash, role, roleTitle, '', status]
    );
    await logSystemEvent(req.user.username, req.user.role, `Created ${role.toLowerCase()} account: ${username.trim()}`, 'User Management', 'info', req.ip);
    res.status(201).json({ success: true, userId: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ success: false, message: 'That username is already in use.' });
    res.status(500).json({ success: false, message: 'Failed to create user.' });
  }
});

app.put('/api/users/:userId', authenticate, requireRole('Admin'), async (req, res) => {
  const { name, username, password, role, status } = req.body;
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId) || ![name, username, role, status].every(value => typeof value === 'string' && value.trim())) {
    return res.status(400).json({ success: false, message: 'Complete valid user details are required.' });
  }
  if (!['Admin', 'Teacher'].includes(role) || !['Active', 'Inactive'].includes(status) || (password && password.length < 12)) {
    return res.status(400).json({ success: false, message: 'Invalid role, status, or password length.' });
  }
  if (userId === req.user.id && (role !== 'Admin' || status !== 'Active')) {
    return res.status(400).json({ success: false, message: 'You cannot deactivate or remove your own administrator access.' });
  }

  try {
    const connection = await db.getConnection();
    try {
      await connection.beginTransaction();

      // Lock all active Admin rows to prevent concurrent deactivation/deletion races
      const [adminRows] = await connection.query(
        'SELECT user_id FROM users WHERE role = ? AND status = ? FOR UPDATE',
        ['Admin', 'Active']
      );
      const activeAdminCount = adminRows.length;

      // Check if the target user exists
      const [targetUsers] = await connection.query(
        'SELECT user_id, username, role, status FROM users WHERE user_id = ?',
        [userId]
      );
      if (!targetUsers.length) {
        await connection.rollback();
        return res.status(404).json({ success: false, message: 'User not found.' });
      }

      const target = targetUsers[0];

      // Prevent deactivating the last active Admin
      if (status === 'Inactive' && target.role === 'Admin' && target.status === 'Active' && activeAdminCount <= 1) {
        await connection.rollback();
        return res.status(400).json({ success: false, message: 'Cannot deactivate the last active Admin account.' });
      }

      const values = [name.trim(), username.trim().toLowerCase(), role, role === 'Admin' ? 'System Administrator' : 'Teacher / Advisor', status];
      let sql = 'UPDATE users SET name=?, username=?, role=?, role_title=?, status=?';
      if (password) { sql += ', password=?'; values.push(await bcrypt.hash(password, 12)); }
      sql += ' WHERE user_id=?'; values.push(userId);
      await connection.query(sql, values);
      if (role !== 'Teacher') {
        await connection.query('DELETE FROM teacher_sections WHERE teacher_id = ?', [userId]);
      }
      await connection.commit();
      await logSystemEvent(req.user.username, req.user.role, `Updated user account ID ${userId}`, 'User Management', 'info', req.ip);
      res.json({ success: true });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ success: false, message: 'That username is already in use.' });
    res.status(500).json({ success: false, message: 'Failed to update user.' });
  }
});

app.delete('/api/users/:userId', authenticate, requireRole('Admin'), async (req, res) => {
  const userId = Number(req.params.userId);
  if (!Number.isInteger(userId) || userId === req.user.id) return res.status(400).json({ success: false, message: 'You cannot delete your own account.' });
  try {
    const connection = await db.getConnection();
    try {
      await connection.beginTransaction();

      // Check if the target user exists
      const [targetUsers] = await connection.query(
        'SELECT user_id, username, role, status FROM users WHERE user_id = ?',
        [userId]
      );
      if (!targetUsers.length) {
        await connection.rollback();
        return res.status(404).json({ success: false, message: 'User not found.' });
      }

      const target = targetUsers[0];

      // If deleting an active Admin, ensure another active Admin remains
      // Lock all active Admin rows to prevent concurrent deletion races
      const [adminRows] = await connection.query(
        'SELECT user_id FROM users WHERE role = ? AND status = ? FOR UPDATE',
        ['Admin', 'Active']
      );
      const activeAdminCount = adminRows.length;
      if (target.role === 'Admin' && target.status === 'Active' && activeAdminCount <= 1) {
        await connection.rollback();
        return res.status(400).json({ success: false, message: 'Cannot delete the last active Admin account.' });
      }

      const [result] = await connection.query('DELETE FROM users WHERE user_id = ?', [userId]);
      if (!result.affectedRows) {
        await connection.rollback();
        return res.status(404).json({ success: false, message: 'User not found.' });
      }
      await connection.commit();
      await logSystemEvent(req.user.username, req.user.role, `Deleted user account ID ${userId}`, 'User Management', 'warning', req.ip);
      res.json({ success: true });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete user.' });
  }
});

// ============================================================================
// 2. STUDENTS & PREDICTIVE ANALYTICS ROUTES
// ============================================================================

// GET /api/students - Returns all students with Decision Tree predictions
app.get('/api/students', authenticate, async (req, res) => {
  try {
    const sections = await accessibleSections(req);
    const requestedSection = typeof req.query.section === 'string' ? req.query.section : '';
    const requestedTerm = typeof req.query.term === 'string' ? req.query.term : (typeof req.query.quarter === 'string' ? req.query.quarter : 'Term 1');

    // Teacher requesting a section they are not assigned to ? 403
    if (!isAdmin(req) && requestedSection && Array.isArray(sections) && !sections.includes(requestedSection)) {
      return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
    }

    let sql = 'SELECT * FROM students';
    const params = [];
    const conditions = [];

    // Scope to teacher's assigned sections
    if (sections !== null) {
      if (sections.length === 0) {
        return res.json({ success: true, count: 0, students: [] });
      }
      conditions.push('section IN (?)');
      params.push(sections);
    }

    if (requestedSection) { conditions.push('section = ?'); params.push(requestedSection); }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY last_name ASC';
    const [students] = await db.query(sql, params);

    // Calculate absence counts from student_attendance (source of truth for daily attendance)
    // Students.absences is a stored field that may not reflect current attendance records.
    // We count Absent records per student from student_attendance for accurate reporting.
    const [absenceRows] = await db.query(
      'SELECT lrn, COUNT(*) as absenceCount FROM student_attendance WHERE status = ? GROUP BY lrn',
      ['Absent']
    );
    const absenceMap = {};
    absenceRows.forEach(r => { absenceMap[String(r.lrn)] = Number(r.absenceCount); });

    // Load assessments for the requested quarter for weighted grade calculation
    // Includes grading_component and subject data for the official grading system.
    const [assessments] = await db.query(
      'SELECT assessment_id, title, type, grading_component, max_score, section, subject, subject_classification, quarter FROM assessments WHERE quarter IN (?)',
      [termAliases(requestedTerm)]
    );
    const [allScores] = await db.query(
      'SELECT assessment_id, lrn, score FROM assessment_scores'
    );
    assessments.forEach(a => { a.quarter = normalizeTerm(a.quarter); });

    // Build score lookup: lrn -> { assessment_id -> score }
    const scoreMap = {};
    allScores.forEach(row => {
      if (!scoreMap[row.lrn]) scoreMap[row.lrn] = {};
      scoreMap[row.lrn][row.assessment_id] = Number(row.score);
    });

    // Authoritative quarterly grade calculation using the official school grading system.
    // Delegates to GradeCalc.calculateQuarterlyGrade which applies subject-specific
    // Written/Oral Works / Performance Tasks / Exams weights.
    function computeQuarterlyGrade(lrn, subjectName, quarter) {
      const studentScoreMap = scoreMap[lrn] || {};
      const result = GradeCalc.calculateQuarterlyGrade(
        assessments,
        quarter,
        subjectName,
        studentScoreMap
      );
      return result.finalGrade; // null when no assessment data exists for this quarter
    }

    function hasAllComponents(lrn, subjectName, quarter) {
      const studentScoreMap = scoreMap[lrn] || {};
      const result = GradeCalc.calculateQuarterlyGrade(assessments, quarter, subjectName, studentScoreMap);
      const c = result.components || {};
      return !!(c['Written/Oral Works'] && c['Written/Oral Works'].hasData && c['Performance Tasks'] && c['Performance Tasks'].hasData && c['Exams'] && c['Exams'].hasData);
    }

    function missingComponents(lrn, subjectName, quarter) {
      const studentScoreMap = scoreMap[lrn] || {};
      const result = GradeCalc.calculateQuarterlyGrade(assessments, quarter, subjectName, studentScoreMap);
      const c = result.components || {};
      const missing = [];
      if (!(c['Written/Oral Works'] && c['Written/Oral Works'].hasData)) missing.push('Written Works (WW)');
      if (!(c['Performance Tasks'] && c['Performance Tasks'].hasData)) missing.push('Performance Tasks (PT)');
      if (!(c['Exams'] && c['Exams'].hasData)) missing.push('Examination');
      return missing;
    }

    // Decision Tree prediction using the JavaScript model
    // For students WITH stored quarterly grades (q1/q2/q3 > 0), use the
    // multi-quarter Decision Tree model with their actual stored grades.
    // For students WITHOUT stored grades, compute Q1 weighted grade from
    // assessments and use the Q1-only Decision Tree model (q1=q2=q3=persistence
    // assumption). The Q1 model was trained on Q1-only features, so it CAN validly
    // predict when only Q1 data exists.
    // Students with no assessment data at all get mlPredictedRisk = null.
    let mlPredictions = [];
    try {
      students.forEach(s => {
        const studentScores = scoreMap[s.lrn] || {};
        const hasScores = Object.keys(studentScores).length > 0;
        if (!hasScores) return;
        const gradeResult = GradeCalc.calculateQuarterlyGrade(
          assessments,
          requestedTerm,
          'General Mathematics',
          studentScores
        );
        const q1Grade = gradeResult.finalGrade;
        if (q1Grade === null || q1Grade === undefined) return;
        const sufficient = !!(gradeResult.components && gradeResult.components['Written/Oral Works'] && gradeResult.components['Written/Oral Works'].hasData && gradeResult.components['Performance Tasks'] && gradeResult.components['Performance Tasks'].hasData && gradeResult.components['Exams'] && gradeResult.components['Exams'].hasData);
        if (!sufficient) return;
        const absences = absenceMap[String(s.lrn)] != null
          ? Number(absenceMap[String(s.lrn)])
          : Number(s.absences || 0);
        const attendanceRate = Number(s.attendance_rate);
  try {
          const pred = predictStudentQ1({
            q1: q1Grade,
            absences: absences,
            attendanceRate: attendanceRate,
            lrn: s.lrn,
            name: `undefined ${s.last_name}`,
          });
          mlPredictions.push(pred);
        } catch (e) {
          // skip invalid data
        }
      });
    } catch (err) {
      console.error('[ML Prediction Error]:', err.message);
    }
    // Merge database record with ML inference
    const enriched = students.map((s) => {
      const ml = mlPredictions.find((p) => String(p.lrn) === String(s.lrn));
      const usesComputedGrade = (Number(s.q1) === 0 && Number(s.q2) === 0 && Number(s.q3) === 0);
      const grade = Number(s.q4);
      const absences = Number(s.absences || 0);
      const hasValidGrade = Number.isFinite(grade);

      let mlPredictedRisk = null;
      let mlRiskLabel = null;
      let mlConfidence = 0;
      let mlProbabilities = null;
      let mlReasons = [];
      let mlIntervention = 'Regular Academic Routine';

      if (ml && ml.mlPredictedRisk) {
        // ML prediction is available - include it in response regardless of
        // whether grades are stored or computed. The final classification
        // uses ML for stored-grade students and rule-based for Q1-only students.
        mlPredictedRisk = ml.mlPredictedRisk;
        mlRiskLabel = ml.mlPredictedLabel;
        mlConfidence = ml.mlConfidence;
        mlProbabilities = ml.mlClassProbabilities;
        mlReasons = ml.reasons;
        mlIntervention = ml.recommendedIntervention;
      }

      // Determine effective grade for rule-based evaluation
      const effectiveGrade = usesComputedGrade ? computeQuarterlyGrade(s.lrn, 'General Mathematics', requestedTerm) : grade;
      const quarterSufficient = usesComputedGrade ? hasAllComponents(s.lrn, 'General Mathematics', requestedTerm) : hasValidGrade;
      const effectiveHasValidGrade = usesComputedGrade ? quarterSufficient : hasValidGrade;

      // Rule-based institutional classification (authoritative for Q1-only)
      const ruleBased = ruleBasedRisk(effectiveHasValidGrade ? effectiveGrade : null, absences);

      // Final risk: use ML when a valid ML prediction is available
      // (stored or computed grade). Q1 model is valid for Q1-only prediction.
      const useMl = ml && ml.mlPredictedRisk && ml.isMLModel === true && effectiveHasValidGrade;

      let finalLevel, finalLabel, finalReasons;
      if (!effectiveHasValidGrade) {
        if (ruleBased.level === 'HIGH' || ruleBased.level === 'MODERATE') {
          finalLevel = ruleBased.level;
          finalLabel = ruleBased.label;
          finalReasons = ruleBased.reasons;
        } else {
          finalLevel = 'INSUFFICIENT_DATA';
          finalLabel = 'INSUFFICIENT DATA';
          const _missing = usesComputedGrade ? missingComponents(s.lrn, 'General Mathematics', requestedTerm) : [];
          finalReasons = [_missing.length ? ('Insufficient data: missing ' + _missing.join(', ')) : 'Insufficient academic data — no assessment records available'];
        }
      } else if (ruleBased.level === 'INSUFFICIENT_DATA') {
        finalLevel = ruleBased.level;
        finalLabel = ruleBased.label;
        finalReasons = ruleBased.reasons;
      } else if (useMl) {
        if (ml.mlRiskLevel === 'HIGH' || ruleBased.level === 'HIGH') {
          finalLevel = 'HIGH';
          finalLabel = 'AT-RISK';
          finalReasons = (ml.mlRiskLevel === 'HIGH' ? (ml.reasons || ruleBased.reasons) : ruleBased.reasons);
        } else if (ruleBased.level === 'MODERATE') {
          finalLevel = 'MODERATE';
          finalLabel = 'MONITOR';
          finalReasons = ruleBased.reasons;
        } else {
          finalLevel = 'LOW';
          finalLabel = 'NOT AT-RISK';
          finalReasons = ml.reasons || ruleBased.reasons;
        }
      } else {
        finalLevel = ruleBased.level;
        finalLabel = ruleBased.label;
        finalReasons = ruleBased.reasons;
      }

      const isAtRisk = finalLevel === 'HIGH';

      return {
        lrn: s.lrn,
        firstName: s.first_name,
        lastName: s.last_name,
        name: `${s.first_name} ${s.last_name}`,
        gender: s.gender,
        dob: s.dob,
        section: s.section,
        strand: s.strand,
        parentName: s.parent_name,
        parentContact: s.parent_contact,
        address: s.address,
        q1: Number(s.q1),
        q2: Number(s.q2),
        q3: Number(s.q3),
        q4: Number(s.q4),
        absences: absenceMap[String(s.lrn)] || Number(s.absences || 0),
        attendanceRate: Number(s.attendance_rate),
        smsSent: Boolean(s.sms_sent),
        // ML Model attributes (null when no valid prediction available)
        mlPredictedRisk,
        mlRiskLabel,
        mlConfidence,
        mlProbabilities,
        mlReasons,
        mlIntervention,
        // Final authoritative risk classification (ML when available & valid, else rule-based)
        riskLevel: finalLevel,
        riskLabel: finalLabel,
        riskReasons: finalReasons,
        // Computed grade from assessments (when stored grades are missing)
        computedGrade: (usesComputedGrade && quarterSufficient) ? effectiveGrade : null,
        // Rule-based institutional classification (separate from ML)
        ruleBased,
      };
    });

    res.json({ success: true, count: enriched.length, students: enriched });
  } catch (err) {
    console.error('[Get Students Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to retrieve students from database.' });
  }
});

// GET /api/students/sections - Dynamic section list with student counts
// Teachers see only their assigned sections; Admins see all sections.
app.get('/api/students/sections', authenticate, async (req, res) => {
  try {
    const teacherId = req.user.id;
    const userRole = req.user.role;
    const requestedGradeLevel = typeof req.query.grade_level === 'string' ? req.query.grade_level : '';
    let sql, params = [];

    if (userRole === 'Admin') {
      if (requestedGradeLevel) {
        sql = `SELECT section, COUNT(*) as student_count FROM students 
               WHERE SUBSTRING_INDEX(section, ' - ', 1) = ? 
               GROUP BY section ORDER BY section`;
        params = [requestedGradeLevel];
      } else {
        sql = `SELECT section, COUNT(*) as student_count FROM students GROUP BY section ORDER BY section`;
      }
    } else {
      if (requestedGradeLevel) {
        sql = `SELECT s.section, COUNT(s.lrn) as student_count 
               FROM students s 
               INNER JOIN teacher_sections ts ON s.section = ts.section 
               WHERE ts.teacher_id = ? 
               AND SUBSTRING_INDEX(s.section, ' - ', 1) = ?
               GROUP BY s.section ORDER BY s.section`;
        params = [teacherId, requestedGradeLevel];
      } else {
        sql = `SELECT s.section, COUNT(s.lrn) as student_count 
               FROM students s 
               INNER JOIN teacher_sections ts ON s.section = ts.section 
               WHERE ts.teacher_id = ? 
               GROUP BY s.section ORDER BY s.section`;
        params = [teacherId];
      }
    }

    const [rows] = await db.query(sql, params);
    res.json({ success: true, sections: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/students/grade-levels - Distinct grade levels extracted from student section names
// Teachers see only grade levels within their assigned sections; Admins see all.
app.get('/api/students/grade-levels', authenticate, async (req, res) => {
  try {
    const teacherId = req.user.id;
    const userRole = req.user.role;
    let sql, params = [];

    if (userRole === 'Admin') {
      sql = `SELECT DISTINCT SUBSTRING_INDEX(section, ' - ', 1) AS grade_level 
             FROM students 
             WHERE section IS NOT NULL AND section != '' AND section LIKE '% - %'
             ORDER BY grade_level`;
    } else {
      sql = `SELECT DISTINCT SUBSTRING_INDEX(s.section, ' - ', 1) AS grade_level 
             FROM students s 
             INNER JOIN teacher_sections ts ON s.section = ts.section 
             WHERE ts.teacher_id = ? 
             AND s.section IS NOT NULL AND s.section != '' AND s.section LIKE '% - %'
             ORDER BY grade_level`;
      params = [teacherId];
    }

    const [rows] = await db.query(sql, params);
    res.json({ success: true, grade_levels: rows.map(r => r.grade_level) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/students/:lrn - Single student detail + ML Prediction
app.get('/api/students/:lrn', authenticate, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM students WHERE lrn = ?', [req.params.lrn]);
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }
    const s = rows[0];
    if (!(await canAccessStudent(req, s))) {
      return res.status(403).json({ success: false, message: 'You are not assigned to this student section.' });
    }

    const [absRows] = await db.query(
      "SELECT lrn, COUNT(*) AS c FROM student_attendance WHERE lrn = ? AND status = 'Absent' GROUP BY lrn",
      [s.lrn]
    );
    const absenceCount = absRows.length ? Number(absRows[0].c) : Number(s.absences || 0);

// Compute Q1 quarterly grade from assessments using the official grading system
    let q1Grade = (s.q1 === null || s.q1 === undefined || Number(s.q1) === 0) ? null : Number(s.q1);
    let assessments = [];
    let scoreMap = {};
    if ((s.q1 === null || s.q1 === undefined || Number(s.q1) === 0) && (s.q2 === null || s.q2 === undefined || Number(s.q2) === 0) && (s.q3 === null || s.q3 === undefined || Number(s.q3) === 0)) {
      [assessments] = await db.query(
        'SELECT assessment_id, title, type, grading_component, max_score, section, subject, subject_classification, quarter FROM assessments WHERE quarter IN (?)',
        [termAliases('Term 1')]
      );
      assessments.forEach(a => { a.quarter = normalizeTerm(a.quarter); });
      const [scores] = await db.query(
        'SELECT assessment_id, score FROM assessment_scores WHERE lrn = ?',
        [s.lrn]
      );
      scoreMap = {};
      scores.forEach(row => { scoreMap[row.assessment_id] = Number(row.score); });

      const gradeResult = GradeCalc.calculateQuarterlyGrade(
        assessments,
        'Term 1',
        'General Mathematics',
        scoreMap
      );
      q1Grade = gradeResult.finalGrade;
    }

    let ml = null;
    let usesStoredGrades = false;
    try {
      // Use stored grades if available; otherwise compute Q1 weighted grade from assessments
      const hasStoredGrades = (s.q1 !== null && s.q1 !== undefined && Number.isFinite(Number(s.q1)) && Number(s.q1) !== 0) || (s.q2 !== null && s.q2 !== undefined && Number.isFinite(Number(s.q2)) && Number(s.q2) !== 0) || (s.q3 !== null && s.q3 !== undefined && Number.isFinite(Number(s.q3)) && Number(s.q3) !== 0);
      if (hasStoredGrades) {
        ml = predictStudent({
          q1: Number(s.q1),
          q2: Number(s.q2),
          q3: Number(s.q3),
        absences: absenceCount,
          attendanceRate: Number(s.attendance_rate),
          lrn: s.lrn,
          name: `${s.first_name} ${s.last_name}`,
        });
        usesStoredGrades = true;
      } else {
        // Compute Q1 weighted grade from assessments and use Q1-only ML model
        const _gr = GradeCalc.calculateQuarterlyGrade(assessments, 'Term 1', 'General Mathematics', scoreMap);
        const _suff = !!(_gr.components && _gr.components['Written/Oral Works'] && _gr.components['Written/Oral Works'].hasData && _gr.components['Performance Tasks'] && _gr.components['Performance Tasks'].hasData && _gr.components['Exams'] && _gr.components['Exams'].hasData);
        if (q1Grade !== null && _suff) {
          ml = predictStudentQ1({
            q1: q1Grade,
        absences: absenceCount,
            attendanceRate: Number(s.attendance_rate),
            lrn: s.lrn,
            name: `${s.first_name} ${s.last_name}`,
          });
        }
      }
    } catch (e) {
      console.warn('[Single Predict Warning]:', e.message);
    }

    res.json({ success: true, student: s, mlPrediction: ml });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/students - Add single or batch students (e.g. from CSV import)
// Protected: only authenticated users may import. teacherId is taken from req.user (never from body).
app.post('/api/students', authenticate, async (req, res) => {
  let students = [];
  const replaceTeacherSections = !Array.isArray(req.body) && req.body && req.body.replaceTeacherSections === true;

  // Support both array format and object format { students: [] }
  if (Array.isArray(req.body)) {
    students = req.body;
  } else if (req.body && Array.isArray(req.body.students)) {
    students = req.body.students;
  } else {
    students = [req.body];
  }

  if (!students.length) return res.status(400).json({ success: false, message: 'No student data provided.' });

  const teacherId = req.user.id; // authenticated user's user_id, never from client
  const userName = req.user.username;
  const userRole = req.user.role;

  // Student records are shared between Admin and Teacher accounts. Imports
  // from either role therefore update the same school roster.
  const isAdmin = userRole === 'Admin';
  if (students.some(student => student && student.lrn && (typeof student.section !== 'string' || !student.section.trim()))) {
    return res.status(400).json({ success: false, message: 'Every imported student must have a section.' });
  }

  // Validate optional Assigned_Subject values against existing teacher-subject-section assignments.
  const assignedSubjects = students
    .map(s => (typeof s?.assignedSubject === 'string' ? s.assignedSubject.trim() : ''))
    .filter(Boolean);
  if (assignedSubjects.length > 0) {
    const [schoolYearRows] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'school_year'");
    const schoolYear = schoolYearRows.length ? schoolYearRows[0].setting_value : '2026 - 2027';
    for (const s of students) {
      const subject = typeof s?.assignedSubject === 'string' ? s.assignedSubject.trim() : '';
      if (!subject) continue;
      const [subjectRows] = await db.query('SELECT subject_name FROM subjects WHERE subject_name = ?', [subject]);
      if (!subjectRows.length) {
        return res.status(400).json({ success: false, message: `Unknown subject "${subject}" in CSV import.` });
      }
      const section = typeof s.section === 'string' ? s.section.trim() : '';
      let assignmentQuery = 'SELECT 1 FROM teacher_subject_sections WHERE section = ? AND subject = ? AND school_year = ? LIMIT 1';
      const params = [section, subject, schoolYear];
      if (userRole !== 'Admin') {
        assignmentQuery = 'SELECT 1 FROM teacher_subject_sections WHERE teacher_id = ? AND section = ? AND subject = ? AND school_year = ? LIMIT 1';
        params.unshift(teacherId);
      }
      const [assignmentRows] = await db.query(assignmentQuery, params);
      if (!assignmentRows.length) {
        return res.status(403).json({
          success: false,
          message: userRole === 'Admin'
            ? `No teacher-subject assignment exists for ${subject} in ${section}. Ask the assigned teacher to create it first.`
            : `You are not assigned to ${subject} in ${section}.`
        });
      }
    }
  }

  try {
    const connection = await db.getConnection();
    await connection.beginTransaction();

    let inserted = 0;
    const newSections = new Set();
    let assignedSections = [];

    try {
      // --- DUPLICATE LRN VALIDATION ---
      // 1. Check for duplicate LRNs within the batch
      const batchLrns = [];
      const batchDuplicates = [];
      const seenLrns = new Set();
      for (const s of students) {
        if (!s.lrn) continue;
        const lrn = String(s.lrn).trim();
        if (seenLrns.has(lrn)) {
          batchDuplicates.push(lrn);
        } else {
          seenLrns.add(lrn);
        }
        batchLrns.push(lrn);
      }

      // 2. Check if any LRN already exists in the database
      const existingConflicts = [];
      if (batchLrns.length > 0) {
        const placeholders = batchLrns.map(() => '?').join(',');
        const [existingRows] = await connection.query(
          `SELECT lrn FROM students WHERE lrn IN (${placeholders})`,
          batchLrns
        );
        existingConflicts.push(...existingRows.map(r => r.lrn));
      }

      // 4. Section authorization: teachers cannot import into existing sections they are not assigned to
      if (!isAdmin) {
        const sectionsInBatch = [...newSections];
        for (const section of sectionsInBatch) {
          const [existingSection] = await connection.query(
            'SELECT 1 FROM students WHERE section = ? LIMIT 1',
            [section]
          );
          if (existingSection.length > 0) {
            // Section already exists in DB — teacher must be assigned to it
            const [assigned] = await connection.query(
              'SELECT 1 FROM teacher_sections WHERE teacher_id = ? AND section = ? LIMIT 1',
              [teacherId, section]
            );
            if (!assigned.length) {
              await connection.rollback();
              connection.release();
              return res.status(403).json({
                success: false,
                message: `You are not assigned to section "${section}". Cannot import students into this section.`
              });
            }
          }
        }
      }

      for (const s of students) {
        if (!s.lrn) continue;
        const section = typeof s.section === 'string' ? s.section.trim() : '';
        if (section) newSections.add(section);

        const grade = value => Number.isFinite(Number(value)) ? Number(value) : 0;
        const absenceCount = Number.isFinite(Number(s.absences)) ? Number(s.absences) : 0;
        const attendanceRate = Number.isFinite(Number(s.attendanceRate ?? s.attendance_rate))
          ? Number(s.attendanceRate ?? s.attendance_rate)
          : 100;

        await connection.query(
          `INSERT INTO students (lrn, first_name, last_name, gender, dob, section, strand, parent_name, parent_contact, address, q1, q2, q3, q4, absences, attendance_rate, sms_sent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            s.lrn, s.firstName || s.first_name || 'Student', s.lastName || s.last_name || 'User', s.gender || 'Male',
            s.dob || '2008-01-01', section, s.strand || 'STEM',
            s.parentName || s.parent_name || '', s.parentContact || s.parent_contact || '', s.address || '',
            grade(s.q1), grade(s.q2), grade(s.q3), grade(s.q4),
            absenceCount, attendanceRate, s.smsSent ? 1 : 0
          ]
        );
        inserted++;
      }

      // Imported sections are added to the teacher's assignments (never replace existing ones).
      if (!isAdmin && newSections.size > 0) {
        for (const section of newSections) {
          const [existing] = await connection.query(
            'SELECT id FROM teacher_sections WHERE teacher_id = ? AND section = ?',
            [teacherId, section]
          );
          if (existing.length === 0) {
            await connection.query(
              'INSERT INTO teacher_sections (teacher_id, section) VALUES (?, ?)',
              [teacherId, section]
            );
            console.log(`[Auto-Section] Assigned teacher ${teacherId} to section: ${section}`);
          }
        }
      }

      if (!isAdmin) {
        const [sectionRows] = await connection.query(
          'SELECT section FROM teacher_sections WHERE teacher_id = ? ORDER BY section',
          [teacherId]
        );
        assignedSections = sectionRows.map(row => row.section);
      }

      await connection.commit();
    } catch (txErr) {
      await connection.rollback();
      // If a concurrent insert caused a duplicate key error, treat as conflict
      if (txErr.code === 'ER_DUP_ENTRY') {
        connection.release();
        return res.status(409).json({
          success: false,
          message: 'Import rejected: one or more LRNs already exist in the database (concurrent import detected). No students were imported.',
          conflictingLrns: []
        });
      }
      throw txErr;
    } finally {
      connection.release();
    }

    await logSystemEvent(userName, userRole, `Imported ${inserted} student records`, 'Student Records', 'info', req.ip);
    res.json({ success: true, count: inserted, sections: isAdmin ? [] : assignedSections, message: `Successfully saved ${inserted} students to MySQL.` });
  } catch (err) {
    console.error('[Insert Student Error]:', err);
    res.status(500).json({ success: false, message: 'Database error saving students.' });
  }
});

// DELETE /api/students - Clear student records (section-specific when ?section= provided)
// Teachers can clear only their assigned sections; Admins can clear any section or all sections.
app.delete('/api/students', authenticate, async (req, res) => {
  try {
    const requestedSection = typeof req.query.section === 'string' ? req.query.section : '';
    const userRole = req.user.role;
    const teacherId = req.user.id;

    // Teachers can only clear their own assigned sections
    if (userRole !== 'Admin' && requestedSection) {
      const [assigned] = await db.query(
        'SELECT 1 FROM teacher_sections WHERE teacher_id = ? AND section = ? LIMIT 1',
        [teacherId, requestedSection]
      );
      if (!assigned.length) {
        return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
      }
    }

    if (requestedSection) {
      // Delete only students from the specified section and their related records
      const [sectionStudents] = await db.query('SELECT lrn FROM students WHERE section = ?', [requestedSection]);
      const lrns = sectionStudents.map(s => s.lrn);

      if (lrns.length > 0) {
        const placeholders = lrns.map(() => '?').join(',');
        await db.query(`DELETE FROM notification_logs WHERE lrn IN (${placeholders})`, lrns);
        await db.query(`DELETE FROM student_attendance WHERE lrn IN (${placeholders})`, lrns);
        await db.query(`DELETE FROM assessment_scores WHERE lrn IN (${placeholders})`, lrns);
      }
      await db.query('DELETE FROM students WHERE section = ?', [requestedSection]);

      await logSystemEvent(req.user.username, req.user.role, `Cleared all student records for section: ${requestedSection}`, 'Student Records', 'warning', req.ip);
      res.json({ success: true, message: `All student records for section "${requestedSection}" cleared successfully from MySQL.`, clearedSection: requestedSection });
    } else {
      // Full clear - Admin only
      if (userRole !== 'Admin') {
        return res.status(403).json({ success: false, message: 'Only administrators can clear all sections.' });
      }
      await db.query('DELETE FROM notification_logs');
      await db.query('DELETE FROM student_attendance');
      await db.query('DELETE FROM assessment_scores');
      await db.query('DELETE FROM students');
      await logSystemEvent(req.user.username, req.user.role, 'Cleared all student records and related data from database for fresh CSV import', 'Student Records', 'warning', req.ip);
      res.json({ success: true, message: 'All student records and related data cleared successfully from MySQL.' });
    }
  } catch (err) {
    console.error('[Delete Students Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to clear students from database.' });
  }
});

// PUT /api/students/:lrn - Update grades / attendance
app.put('/api/students/:lrn', authenticate, async (req, res) => {
  const { lrn } = req.params;
  const { q1, q2, q3, q4, absences, attendanceRate, parentContact, parentName, address } = req.body;

  try {
    const validationError = validateStudentUpdate(req.body);
    if (validationError) return res.status(400).json({ success: false, message: validationError });

    const [students] = await db.query('SELECT section FROM students WHERE lrn = ?', [lrn]);
    if (students.length === 0) return res.status(404).json({ success: false, message: 'Student not found.' });
    if (!(await canAccessStudent(req, students[0]))) {
      return res.status(403).json({ success: false, message: 'You are not assigned to this student section.' });
    }

    await db.query(
      `UPDATE students SET 
        q1 = COALESCE(?, q1),
        q2 = COALESCE(?, q2),
        q3 = COALESCE(?, q3),
        q4 = COALESCE(?, q4),
        absences = COALESCE(?, absences),
        attendance_rate = COALESCE(?, attendance_rate),
        parent_contact = COALESCE(?, parent_contact),
        parent_name = COALESCE(?, parent_name),
        address = COALESCE(?, address)
       WHERE lrn = ?`,
      [q1, q2, q3, q4, absences, attendanceRate, parentContact, parentName, address, lrn]
    );

    await logSystemEvent(req.user.username, req.user.role, `Updated student record for LRN ${lrn}`, 'Student Records', 'info', req.ip);
    res.json({ success: true, message: 'Student updated successfully.' });
  } catch (err) {
    console.error('[Update Student Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to update student.' });
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================
app.get('/api/health', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT 1 AS ok');
    res.json({ success: true, status: 'healthy', database: rows && rows[0] && rows[0].ok === 1 ? 'connected' : 'unknown' });
  } catch (err) {
    res.status(503).json({ success: false, status: 'unhealthy', database: 'disconnected' });
  }
});

// ============================================================================
// ACADEMIC TERM DATES (shared school-wide configuration)
// ============================================================================
app.get('/api/active-academic-term', authenticate, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'active_academic_term'");
    if (!rows.length) return res.json({ success: true, configured: false, term: null });
    const term = Number(rows[0].setting_value);
    if (![1, 2, 3].includes(term)) return res.json({ success: true, configured: false, term: null });
    res.json({ success: true, configured: true, term });
  } catch (err) {
    console.error('[Active Term GET Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to load active academic term.' });
  }
});

app.put('/api/active-academic-term', authenticate, requireRole('Teacher', 'Admin'), async (req, res) => {
  try {
    const term = Number(req.body?.term);
    if (![1, 2, 3].includes(term)) return res.status(400).json({ success: false, message: 'Active term must be 1, 2, or 3.' });
    const value = String(term);
    await db.query(
      "INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?",
      ['active_academic_term', value, value]
    );
    res.json({ success: true, configured: true, term });
  } catch (err) {
    console.error('[Active Term PUT Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to save active academic term.' });
  }
});

// ============================================================================
// TEACHER SUBJECT-SECTION ASSIGNMENTS
// ============================================================================
app.get('/api/teacher-subject-sections', authenticate, async (req, res) => {
  try {
    const requestedSection = typeof req.query.section === 'string' ? req.query.section : '';
    const requestedTeacherId = req.user.role === 'Admin' && req.query.teacherId ? Number(req.query.teacherId) : req.user.id;
    if (req.user.role !== 'Admin' && requestedTeacherId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'You can only view your own subject assignments.' });
    }
    let sql = 'SELECT id, teacher_id, section, subject, school_year, is_default, created_at FROM teacher_subject_sections WHERE teacher_id = ?';
    const params = [requestedTeacherId];
    if (requestedSection) { sql += ' AND section = ?'; params.push(requestedSection); }
    sql += ' ORDER BY section, is_default DESC, subject';
    const [rows] = await db.query(sql, params);
    res.json({ success: true, assignments: rows });
  } catch (err) {
    console.error('[Subject Assignments GET Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to load subject assignments.' });
  }
});

app.post('/api/teacher-subject-sections', authenticate, requireRole('Teacher'), async (req, res) => {
  try {
    const section = typeof req.body?.section === 'string' ? req.body.section.trim() : '';
    const subject = typeof req.body?.subject === 'string' ? req.body.subject.trim() : '';
    const schoolYear = typeof req.body?.schoolYear === 'string' ? req.body.schoolYear.trim() : '2026 - 2027';
    const isDefault = req.body?.isDefault === true || req.body?.isDefault === 1 || req.body?.isDefault === '1';
    if (!section || !subject) return res.status(400).json({ success: false, message: 'Section and subject are required.' });

    const [assigned] = await db.query('SELECT 1 FROM teacher_sections WHERE teacher_id = ? AND section = ? LIMIT 1', [req.user.id, section]);
    if (!assigned.length) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });

    const [subjectRows] = await db.query('SELECT subject_name FROM subjects WHERE subject_name = ?', [subject]);
    if (!subjectRows.length) return res.status(400).json({ success: false, message: 'Unknown subject.' });

    const [existing] = await db.query('SELECT id FROM teacher_subject_sections WHERE teacher_id = ? AND section = ? AND subject = ? AND school_year = ?', [req.user.id, section, subject, schoolYear]);
    if (existing.length) return res.status(409).json({ success: false, message: 'This subject is already assigned to the section.' });

    if (isDefault) {
      await db.query('UPDATE teacher_subject_sections SET is_default = 0 WHERE teacher_id = ? AND section = ? AND school_year = ?', [req.user.id, section, schoolYear]);
    }

    const [result] = await db.query(
      'INSERT INTO teacher_subject_sections (teacher_id, section, subject, school_year, is_default) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, section, subject, schoolYear, isDefault ? 1 : 0]
    );
    res.status(201).json({ success: true, id: result.insertId });
  } catch (err) {
    console.error('[Subject Assignments POST Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to create subject assignment.' });
  }
});

app.delete('/api/teacher-subject-sections/:id', authenticate, requireRole('Teacher'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [rows] = await db.query('SELECT teacher_id FROM teacher_subject_sections WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Assignment not found.' });
    if (rows[0].teacher_id !== req.user.id) return res.status(403).json({ success: false, message: 'You can only delete your own subject assignments.' });
    await db.query('DELETE FROM teacher_subject_sections WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('[Subject Assignments DELETE Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to delete subject assignment.' });
  }
});

async function getAcademicTermDates() {
  const [rows] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'academic_term_dates'");
  if (!rows.length) return null;
  try { return JSON.parse(rows[0].setting_value); } catch (e) { return null; }
}

function validateTermDates(input) {
  const terms = ['term1', 'term2', 'term3'];
  const parsed = {};
  for (const term of terms) {
    const start = input?.[term]?.start;
    const end = input?.[term]?.end;
    if (!start || !end) return { valid: false, message: 'All three terms require a start and end date.' };
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
      return { valid: false, message: 'Term dates must use YYYY-MM-DD format.' };
    }
    const startDate = new Date(start + 'T00:00:00');
    const endDate = new Date(end + 'T00:00:00');
    if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
      return { valid: false, message: 'Invalid term date.' };
    }
    if (startDate > endDate) {
      return { valid: false, message: 'A term start date cannot be after its end date.' };
    }
    parsed[term] = { start, end, startDate, endDate };
  }
  if (parsed.term1.endDate >= parsed.term2.startDate) {
    return { valid: false, message: 'Term 1 and Term 2 must not overlap and must be chronological.' };
  }
  if (parsed.term2.endDate >= parsed.term3.startDate) {
    return { valid: false, message: 'Term 2 and Term 3 must not overlap and must be chronological.' };
  }
  return {
    valid: true,
    dates: {
      term1: { start: parsed.term1.start, end: parsed.term1.end },
      term2: { start: parsed.term2.start, end: parsed.term2.end },
      term3: { start: parsed.term3.start, end: parsed.term3.end },
    },
  };
}

app.get('/api/academic-term-dates', authenticate, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'academic_term_dates'");
    if (!rows.length) return res.json({ success: true, configured: false, dates: null });
    let dates = null;
    try { dates = JSON.parse(rows[0].setting_value); } catch (e) { dates = null; }
    return res.json({ success: true, configured: !!dates, dates });
  } catch (err) {
    console.error('[Term Dates GET Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to load academic term dates.' });
  }
});

app.put('/api/academic-term-dates', authenticate, requireRole('Teacher', 'Admin'), async (req, res) => {
  try {
    const payload = req.body && req.body.dates ? req.body.dates : req.body;
    const validation = validateTermDates(payload);
    if (!validation.valid) return res.status(400).json({ success: false, message: validation.message });
    const value = JSON.stringify(validation.dates);
    await db.query(
      "INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?",
      ['academic_term_dates', value, value]
    );
    res.json({ success: true, configured: true, dates: validation.dates });
  } catch (err) {
    console.error('[Term Dates PUT Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to save academic term dates.' });
  }
});

app.get('/api/academic/latest-assessment-date', authenticate, async (req, res) => {
  try {
    const section = typeof req.query.section === 'string' ? req.query.section : '';
    if (!section) return res.status(400).json({ success: false, message: 'Section is required.' });
    if (!(await canAccessStudent(req, { section }))) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
    const key = 'latest_assessment_date:' + section;
    const [rows] = await db.query('SELECT setting_value FROM settings WHERE setting_key = ?', [key]);
    if (!rows.length) return res.json({ success: true, date: null });
    return res.json({ success: true, date: rows[0].setting_value });
  } catch (err) {
    console.error('[Latest Assessment Date GET Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to load latest assessment date.' });
  }
});

// ============================================================================
// ADMIN: CLEAR ACADEMIC DATA (assessments, scores, attendance, logs)
// ============================================================================
app.post('/api/admin/clear-academic-data', authenticate, requireRole('Admin'), async (req, res) => {
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    await connection.query('DELETE FROM assessment_scores');
    await connection.query('DELETE FROM assessments');
    await connection.query('DELETE FROM student_attendance');
    await connection.query('DELETE FROM notification_logs');
    await connection.query('DELETE FROM system_logs');
    await connection.commit();
    res.json({ success: true, message: 'Academic data cleared successfully.' });
  } catch (err) {
    try { await connection.rollback(); } catch (rollbackErr) {}
    console.error('[Clear Academic Data Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to clear academic data.' });
  } finally {
    connection.release();
  }
});

async function getAssessmentForRequest(req, assessmentId) {
  const [rows] = await db.query('SELECT * FROM assessments WHERE assessment_id = ?', [assessmentId]);
  if (!rows.length) return null;
  if (!(await canAccessStudent(req, { section: rows[0].section }))) return false;
  return rows[0];
}

app.get('/api/assessments', authenticate, async (req, res) => {
  try {
    const sections = await accessibleSections(req);
    const requestedSection = typeof req.query.section === 'string' ? req.query.section : '';
    const requestedSubject = typeof req.query.subject === 'string' ? req.query.subject : '';
    const requestedTerm = typeof req.query.term === 'string' ? req.query.term : (typeof req.query.quarter === 'string' ? req.query.quarter : '');
    const requestedQuarter = typeof req.query.quarter === 'string' ? req.query.quarter : '';
    let sql = 'SELECT assessment_id AS id, title, type, grading_component, subject_classification, assessment_date AS date, max_score AS max, section, subject, quarter FROM assessments';
    const params = [];
    const conditions = [];
    if (sections !== null) {
      if (sections.length === 0) {
        return res.json({ success: true, assessments: [] });
      }
      conditions.push('section IN (?)'); params.push(sections);
    } else if (requestedSection) { conditions.push('section = ?'); params.push(requestedSection); }
    if (requestedSubject) { conditions.push('subject = ?'); params.push(requestedSubject); }
    if (requestedTerm) { conditions.push('quarter IN (?)'); params.push(termAliases(requestedTerm)); }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY assessment_date ASC, assessment_id ASC';
    const [assessments] = await db.query(sql, params);
    assessments.forEach(a => { a.quarter = normalizeTerm(a.quarter); });
    res.json({ success: true, assessments });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve assessments.' });
  }
});

app.post('/api/assessments', authenticate, async (req, res) => {
  const { title, type = 'Activity', max, section, subject = 'General Mathematics', quarter = 'Term 1', gradingComponent } = req.body;
  const normalizedQuarter = normalizeTerm(quarter);
  const score = Number(max);
  if (typeof title !== 'string' || !title.trim() || !Number.isFinite(score) || score < 1 || score > 100 || !section) {
    return res.status(400).json({ success: false, message: 'Title, section, and a maximum score from 1 to 100 are required.' });
  }
  if (!(await canAccessStudent(req, { section }))) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });

  // Validate assessment date against configured academic term dates when available.
  const assessmentDate = typeof req.body.date === 'string' ? req.body.date : '';
  if (assessmentDate) {
    const configuredDates = await getAcademicTermDates();
    if (configuredDates) {
      const inConfiguredTerm = Object.values(configuredDates).some(range => assessmentDate >= range.start && assessmentDate <= range.end);
      if (!inConfiguredTerm) {
        return res.status(400).json({ success: false, message: 'Assessment date must fall within a configured academic term.' });
      }
    }
  }

  // Validate grading component and type pairing
  const component = gradingComponent || GradeCalc.typeToComponent(type) || GradeCalc.COMPONENT_WW;
  if (!GradeCalc.ALL_COMPONENTS.includes(component)) {
    return res.status(400).json({ success: false, message: 'Invalid grading component.' });
  }
  if (!GradeCalc.isValidTypeForComponent(type, component)) {
    const validTypes = GradeCalc.getApplicableTypes(component).join(', ');
    return res.status(400).json({ success: false, message: `Type "${type}" is not valid for ${component}. Valid types: ${validTypes}.` });
  }

  // Multiple examination records are allowed per subject/term.
  // Exam scores are aggregated by total earned / total possible points.

  // Determine subject classification from the subjects table
  let subjectClassification = null;
  try {
    const [subjectRows] = await db.query(
      'SELECT classification AS subject_classification, ww_weight, pt_weight, exam_weight FROM subjects WHERE LOWER(subject_name) = LOWER(?) LIMIT 1',
      [subject]
    );
    subjectClassification = subjectRows.length > 0 ? subjectRows[0].subject_classification : GradeCalc.getSubjectClassification(subject);

     const philDate = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Manila' });
     const finalAssessmentDate = assessmentDate || philDate;
     const [result] = await db.query(
       'INSERT INTO assessments (title, type, grading_component, assessment_date, max_score, section, subject, subject_classification, quarter, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
       [title.trim(), type, component, finalAssessmentDate, score, section, subject, subjectClassification, normalizedQuarter, req.user.id]
     );
     await logSystemEvent(req.user.username, req.user.role, `Created assessment: ${title.trim()} (${component})`, 'Academic Records', 'info', req.ip);
     // Store the latest assessment date for this section (shared calendar sync).
     const dateSettingKey = 'latest_assessment_date:' + section;
     const [existing] = await db.query('SELECT setting_key FROM settings WHERE setting_key = ?', [dateSettingKey]);
     if (existing.length) {
       await db.query('UPDATE settings SET setting_value = ? WHERE setting_key = ?', [finalAssessmentDate, dateSettingKey]);
     } else {
       await db.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)', [dateSettingKey, finalAssessmentDate]);
     }
     res.status(201).json({ success: true, id: result.insertId, date: finalAssessmentDate, gradingComponent: component, subjectClassification });
  } catch (err) {
    console.error('[GradeCalc] Error looking up subject classification:', err.message);
    subjectClassification = GradeCalc.getSubjectClassification(subject);
    res.status(500).json({ success: false, message: 'Failed to create assessment.' });
  }
});

app.put('/api/assessments/:id', authenticate, async (req, res) => {
  const assessment = await getAssessmentForRequest(req, req.params.id);
  if (assessment === false) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
  if (!assessment) return res.status(404).json({ success: false, message: 'Assessment not found.' });
  const { title, type, max, date, gradingComponent } = req.body;
  const score = Number(max);
  if (typeof title !== 'string' || !title.trim() || !Number.isFinite(score) || score < 1 || score > 100) return res.status(400).json({ success: false, message: 'Valid title and maximum score are required.' });

  const component = gradingComponent || GradeCalc.typeToComponent(type || assessment.type) || assessment.grading_component || GradeCalc.COMPONENT_WW;
  if (!GradeCalc.ALL_COMPONENTS.includes(component)) {
    return res.status(400).json({ success: false, message: 'Invalid grading component.' });
  }
  if (type && !GradeCalc.isValidTypeForComponent(type, component)) {
    const validTypes = GradeCalc.getApplicableTypes(component).join(', ');
    return res.status(400).json({ success: false, message: `Type "${type}" is not valid for ${component}. Valid types: ${validTypes}.` });
  }

  const assessmentDate = typeof date === 'string' && date ? date : assessment.assessment_date;
  const configuredDates = await getAcademicTermDates();
  if (configuredDates && assessmentDate) {
    const inConfiguredTerm = Object.values(configuredDates).some(range => assessmentDate >= range.start && assessmentDate <= range.end);
    if (!inConfiguredTerm) {
      return res.status(400).json({ success: false, message: 'Assessment date must fall within a configured academic term.' });
    }
  }

  // Multiple examination records are allowed per subject/term.
  // Exam scores are aggregated by total earned / total possible points.

  try {
    await db.query(
      'UPDATE assessments SET title=?, type=?, grading_component=?, assessment_date=?, max_score=? WHERE assessment_id=?',
      [title.trim(), type || assessment.type, component, assessmentDate, score, assessment.assessment_id]
    );
    // Store the latest assessment date for this section.
    const dateSettingKey = 'latest_assessment_date:' + assessment.section;
    const [existing] = await db.query('SELECT setting_key FROM settings WHERE setting_key = ?', [dateSettingKey]);
    if (existing.length) {
      await db.query('UPDATE settings SET setting_value = ? WHERE setting_key = ?', [assessmentDate, dateSettingKey]);
    } else {
      await db.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)', [dateSettingKey, assessmentDate]);
    }
    res.json({ success: true, date: assessmentDate });
  } catch (err) { res.status(500).json({ success: false, message: 'Failed to update assessment.' }); }
});

app.delete('/api/assessments/:id', authenticate, async (req, res) => {
  const assessment = await getAssessmentForRequest(req, req.params.id);
  if (assessment === false) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
  if (!assessment) return res.status(404).json({ success: false, message: 'Assessment not found.' });
  try {
    // Use transaction to delete assessment and its scores atomically
    const assessmentId = assessment.assessment_id;
    await db.query('START TRANSACTION');
    await db.query('DELETE FROM assessment_scores WHERE assessment_id = ?', [assessmentId]);
    await db.query('DELETE FROM assessments WHERE assessment_id = ?', [assessmentId]);
    await db.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await db.query('ROLLBACK');
    res.status(500).json({ success: false, message: 'Failed to delete assessment.' });
  }
});

app.get('/api/assessments/:id/scores', authenticate, async (req, res) => {
  const assessment = await getAssessmentForRequest(req, req.params.id);
  if (assessment === false) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
  if (!assessment) return res.status(404).json({ success: false, message: 'Assessment not found.' });
  try {
    const [scores] = await db.query('SELECT lrn, score FROM assessment_scores WHERE assessment_id = ?', [assessment.assessment_id]);
    res.json({ success: true, scores });
  } catch (err) { res.status(500).json({ success: false, message: 'Failed to retrieve assessment scores.' }); }
});

app.put('/api/assessments/:id/scores', authenticate, async (req, res) => {
  const assessment = await getAssessmentForRequest(req, req.params.id);
  if (assessment === false) return res.status(403).json({ success: false, message: 'You are not assigned to this section.' });
  if (!assessment) return res.status(404).json({ success: false, message: 'Assessment not found.' });
  const scores = Array.isArray(req.body.scores) ? req.body.scores : [];
  try {
    for (const row of scores) {
      const score = Number(row.score);
      if (!row.lrn || !Number.isFinite(score) || score < 0 || score > Number(assessment.max_score)) continue;
      const [students] = await db.query('SELECT 1 FROM students WHERE lrn = ? AND section = ?', [row.lrn, assessment.section]);
      if (!students.length) continue;
      await db.query('INSERT INTO assessment_scores (assessment_id, lrn, score) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE score=VALUES(score)', [assessment.assessment_id, row.lrn, score]);
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, message: 'Failed to save assessment scores.' }); }
});


  // ============================================================================
  // 3b. SUBJECT MANAGEMENT
  // ============================================================================

  // GET /api/subjects - Get list of available subjects with classification and weights
  app.get('/api/subjects', authenticate, async (req, res) => {
    try {
      const sections = await accessibleSections(req);
      // Pull subjects from the subjects table (authoritative classifications + weights)
      let sql = 'SELECT subject_name AS subject, classification, ww_weight, pt_weight, exam_weight FROM subjects';
      const params = [];
      if (sections !== null) {
        if (sections.length === 0) {
          // No sections assigned: still return General Mathematics default
          return res.json({
            success: true,
            subjects: [{
              subject: 'General Mathematics',
              classification: 'Core',
              wwWeight: 0.20,
              ptWeight: 0.50,
              examWeight: 0.30,
            }]
          });
        }
      }
      const [rows] = await db.query(sql, params);
      const subjects = rows.map(r => ({
        subject: r.subject,
        classification: r.classification,
        wwWeight: Number(r.ww_weight),
        ptWeight: Number(r.pt_weight),
        examWeight: Number(r.exam_weight),
      }));
      // Always include General Mathematics as the default if not present
      if (!subjects.some(s => s.subject === 'General Mathematics')) {
        subjects.unshift({
          subject: 'General Mathematics',
          classification: 'Core',
          wwWeight: 0.20,
          ptWeight: 0.50,
          examWeight: 0.30,
        });
      }
      res.json({ success: true, subjects });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to retrieve subjects.' });
    }
  });

  // POST /api/subjects - Create a new subject with optional classification
  app.post('/api/subjects', authenticate, async (req, res) => {
    const { subject, classification = 'Core' } = req.body;
    if (!subject || typeof subject !== 'string' || !subject.trim()) {
      return res.status(400).json({ success: false, message: 'Subject name is required.' });
    }
    const cleanSubject = subject.trim();
    // Validate classification
    if (!GradeCalc.SUBJECT_CLASSIFICATIONS.hasOwnProperty(classification)) {
      return res.status(400).json({ success: false, message: 'Invalid subject classification.' });
    }
    const weights = GradeCalc.SUBJECT_CLASSIFICATIONS[classification];
    // Prevent duplicates (case-insensitive) in both tables
    try {
      const [existingSubject] = await db.query(
        'SELECT subject_name FROM subjects WHERE LOWER(subject_name) = LOWER(?) LIMIT 1',
        [cleanSubject]
      );
      if (existingSubject.length > 0) {
        return res.status(409).json({ success: false, message: 'Subject already exists.' });
      }
      const [existingAssessment] = await db.query(
        'SELECT subject FROM assessments WHERE LOWER(subject) = LOWER(?) LIMIT 1',
        [cleanSubject]
      );
      if (existingAssessment.length > 0) {
        return res.status(409).json({ success: false, message: 'Subject already exists.' });
      }
      // Register subject in the subjects table with official weights
      await db.query(
        'INSERT INTO subjects (subject_name, classification, ww_weight, pt_weight, exam_weight, description) VALUES (?, ?, ?, ?, ?, ?)',
        [cleanSubject, classification, weights.ww, weights.pt, weights.exam, GradeCalc.SUBJECT_CLASSIFICATIONS[classification].label]
      );
      // Create a minimal assessment to register the subject in the assessments table (backward compat)
      const [result] = await db.query(
        'INSERT INTO assessments (title, type, grading_component, assessment_date, max_score, section, subject, subject_classification, quarter, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [`${cleanSubject} - Initial`, 'Activity', GradeCalc.COMPONENT_WW, new Date().toISOString().slice(0, 10), 100, '', cleanSubject, classification, 'Term 1', req.user.id]
      );
      await logSystemEvent(req.user.username, req.user.role, `Created subject: ${cleanSubject} (${classification})`, 'Academic Records', 'info', req.ip);
      res.status(201).json({ success: true, subject: cleanSubject, classification, id: result.insertId });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to create subject.' });
    }
  });

// ============================================================================
// 4. STUDENT ATTENDANCE (Per-Subject)
// ============================================================================

// GET /api/attendance - Fetch attendance records for a section/subject/date
app.get('/api/attendance', authenticate, async (req, res) => {
  try {
    const sections = await accessibleSections(req);
    const requestedSection = typeof req.query.section === 'string' ? req.query.section : '';
    const requestedSubject = typeof req.query.subject === 'string' ? req.query.subject : '';
    const requestedDate = typeof req.query.date === 'string' ? req.query.date : '';
    const requestedTerm = typeof req.query.term === 'string' ? req.query.term : '';

    let sql = 'SELECT id, lrn, subject, date, status, absence_type, remarks FROM student_attendance';
    const params = [];
    const conditions = [];

    if (sections !== null) {
      if (sections.length === 0) {
        return res.json({ success: true, attendance: [], hasAssessmentSession: false });
      }
      conditions.push('lrn IN (SELECT lrn FROM students WHERE section IN (?))'); params.push(sections);
    } else if (requestedSection) { conditions.push('lrn IN (SELECT lrn FROM students WHERE section = ?)'); params.push(requestedSection); }
    if (requestedSubject) { conditions.push('subject = ?'); params.push(requestedSubject); }
    if (requestedDate) { conditions.push('date = ?'); params.push(requestedDate); }
    if (requestedTerm) {
      const termMatch = String(requestedTerm).match(/(\d+)/);
      const termNumber = termMatch ? termMatch[1] : '';
      const termKey = 'term' + termNumber;
      const [cfgRows] = await db.query("SELECT setting_value FROM settings WHERE setting_key = 'academic_term_dates'");
      if (!cfgRows.length) {
        return res.status(400).json({ success: false, message: 'Academic term dates are not configured.' });
      }
      let cfg = null;
      try { cfg = JSON.parse(cfgRows[0].setting_value); } catch (e) { cfg = null; }
      const range = cfg ? cfg[termKey] : null;
      if (!range || !range.start || !range.end) {
        return res.status(400).json({ success: false, message: 'Requested term is not configured.' });
      }
      conditions.push('date >= ? AND date <= ?');
      params.push(range.start, range.end);
    }

    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY subject, date, lrn';

    const [rows] = await db.query(sql, params);

    // Determine whether an assessment session exists for this date/section/subject.
    // An assessment record serves as the attendance session marker: its presence
    // means the date is available for attendance taking, even if no student
    // attendance rows have been recorded yet.
    let hasAssessmentSession = false;
    if (requestedDate) {
      const assessmentConditions = ['assessment_date = ?'];
      const assessmentParams = [requestedDate];
      if (requestedSubject) { assessmentConditions.push('subject = ?'); assessmentParams.push(requestedSubject); }
      if (sections !== null) {
        assessmentConditions.push('section IN (?)'); assessmentParams.push(sections);
      } else if (requestedSection) {
        assessmentConditions.push('section = ?'); assessmentParams.push(requestedSection);
      }
      const [assessmentRows] = await db.query(
        'SELECT 1 FROM assessments WHERE ' + assessmentConditions.join(' AND ') + ' LIMIT 1',
        assessmentParams
      );
      hasAssessmentSession = assessmentRows.length > 0;
    }

    res.json({ success: true, attendance: rows, hasAssessmentSession });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to retrieve attendance.' });
  }
});

// POST /api/attendance - Save/upsert attendance records (bulk)
app.post('/api/attendance', authenticate, async (req, res) => {
  const records = Array.isArray(req.body.records) ? req.body.records : [];
  if (!records.length) return res.status(400).json({ success: false, message: 'No attendance records provided.' });

  try {
    for (const r of records) {
      if (!r.lrn || !r.subject || !r.date || !r.status) continue;

      // Verify student exists and user has access
      const [students] = await db.query('SELECT section FROM students WHERE lrn = ?', [r.lrn]);
      if (!students.length) continue;
      if (!(await canAccessStudent(req, { section: students[0].section }))) {
        return res.status(403).json({ success: false, message: 'You are not assigned to this student section.' });
      }

      await db.query(
        `INSERT INTO student_attendance (lrn, subject, date, status, absence_type, remarks)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE status=VALUES(status), absence_type=VALUES(absence_type), remarks=VALUES(remarks)`,
        [r.lrn, r.subject, r.date, r.status, r.absence_type || null, r.remarks || null]
      );
    }
    await logSystemEvent(req.user.username, req.user.role, 'Saved attendance records (' + records.length + ')', 'Attendance', 'info', req.ip);
    res.json({ success: true, saved: records.length });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to save attendance.' });
  }
});

// ============================================================================
// 5. MACHINE LEARNING MODEL MANAGEMENT & EVALUATION
// ============================================================================

// GET /api/ml/metrics - Retrieve model evaluation metrics and Decision Tree rules
app.get('/api/ml/metrics', authenticate, (req, res) => {
  const rulesPath = path.join(__dirname, 'ml', 'models', 'tree_rules.txt');

  try {
    const metadata = getModelMetadata();
    let treeRules = '';
    if (fs.existsSync(rulesPath)) {
      treeRules = fs.readFileSync(rulesPath, 'utf8');
    }
    res.json({
      success: true,
      metadata: metadata,
      treeRules: treeRules
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/ml/predict - Ad-hoc feature prediction
app.post('/api/ml/predict', authenticate, async (req, res) => {
  const { q1, q2, q3, absences, attendanceRate, lrn, name } = req.body;
  try {
    const result = predictStudent({ q1, q2, q3, absences, attendanceRate, lrn, name });
    res.json({ success: true, prediction: result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================================
// 4. SMS NOTIFICATION GATEWAY (TextBee & Simulator)
// ============================================================================

// POST /api/sms/send
app.post('/api/sms/send', authenticate, async (req, res) => {
  const { lrn, parentContact, message } = req.body;

  if (!lrn || !parentContact || !message) {
    return res.status(400).json({ success: false, message: 'Missing required SMS parameters (lrn, parentContact, message).' });
  }

  const connection = await db.getConnection();
  const lockName = 'sms_dispatch_' + String(lrn);
  let lockAcquired = false;
  try {
    const [lockRows] = await connection.query('SELECT GET_LOCK(?, 10) AS acquired', [lockName]);
    if (!lockRows || !lockRows[0] || !lockRows[0].acquired) {
      return res.status(503).json({ success: false, message: 'SMS dispatch is already in progress. Please retry.' });
    }
    lockAcquired = true;

    const [students] = await connection.query('SELECT lrn, section, parent_contact FROM students WHERE lrn = ?', [lrn]);
    if (students.length === 0) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }
    const student = students[0];
    if (!(await canAccessStudent(req, student))) {
      return res.status(403).json({ success: false, message: 'You are not assigned to this student section.' });
    }
    if (student.parent_contact !== parentContact) {
      return res.status(400).json({ success: false, message: 'Parent contact must match the student record.' });
    }

    // 1. Duplicate alert prevention check if sent within the last 60 minutes
    const [recent] = await connection.query(
      `SELECT log_id, date_sent FROM notification_logs 
       WHERE lrn = ? AND status LIKE 'Delivered%' AND date_sent >= NOW() - INTERVAL 1 HOUR LIMIT 1`,
      [lrn]
    );

    if (recent.length > 0) {
      return res.status(429).json({
        success: false,
        message: 'Duplicate Alert Protection: An SMS alert was already dispatched to this parent in the past hour.'
      });
    }

    // 2. Fetch SMS gateway settings
    const [settingsRows] = await connection.query('SELECT setting_key, setting_value FROM settings');
    const settings = {};
    settingsRows.forEach(r => settings[r.setting_key] = r.setting_value);

    const mode = settings.sms_gateway_mode || 'simulation';
    const apiKey = process.env.TEXTBEE_API_KEY;
    const deviceId = process.env.TEXTBEE_DEVICE_ID;
    let deliveryStatus = 'Queued (TextBee Simulator)';
    let deliveryFailed = false;

    if (mode === 'live') {
      if (!apiKey || !deviceId) {
        return res.status(400).json({
          success: false,
          message: 'TextBee is not fully configured. Please set TEXTBEE_API_KEY and TEXTBEE_DEVICE_ID environment variables.'
        });
      }
      try {
        const payload = {
          recipients: [parentContact],
          message: message
        };
        if (deviceId) {
          payload.deviceId = deviceId;
        }

        const tbRes = await fetch('https://api.textbee.dev/api/v1/gateway/send-sms', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey
          },
          body: JSON.stringify(payload)
        });
        const tbJson = await tbRes.json().catch(() => null);
        if (!tbRes.ok) {
          throw new Error(`TextBee returned HTTP ${tbRes.status}${tbJson?.data?.message ? `: ${tbJson.data.message}` : ''}`);
        }
        if (tbJson.data && tbJson.data.success) {
          // TextBee 200 means accepted/queued, NOT delivered
          deliveryStatus = 'Queued (TextBee API)';
        } else {
          throw new Error(`TextBee API returned success=false: ${tbJson.data?.message || 'Unknown error'}`);
        }
      } catch (liveErr) {
        console.error('[Live TextBee Call Failed]:', liveErr.message);
        deliveryStatus = 'Failed (TextBee API)';
        deliveryFailed = true;
      }
    }

    // 3. Record in database notification_logs
    const [insertResult] = await connection.query(
      'INSERT INTO notification_logs (lrn, parent_contact, message, status, date_sent, user_id) VALUES (?, ?, ?, ?, NOW(), ?)',
      [lrn, parentContact, message, deliveryStatus, req.user.id]
    );

    // 4. Only mark the student as notified after a successful delivery.
    if (!deliveryFailed) {
      await connection.query('UPDATE students SET sms_sent = 1 WHERE lrn = ?', [lrn]);
    }

    // 5. System audit log
    await logSystemEvent(
      req.user.username,
      req.user.role,
      `${deliveryFailed ? 'Failed to dispatch' : 'Dispatched'} SMS Notice to ${parentContact} (LRN: ${lrn})`,
      'SMS Gateway',
      deliveryFailed ? 'warning' : 'info',
      req.ip
    );

    if (deliveryFailed) {
      return res.status(502).json({
        success: false,
        message: 'The SMS gateway did not accept the message. The failure was logged; please retry after checking the gateway settings.',
        logId: insertResult.insertId,
        status: deliveryStatus
      });
    }

    res.json({
      success: true,
      message: 'SMS Notification processed successfully.',
      logId: insertResult.insertId,
      status: deliveryStatus
    });
  } catch (err) {
    console.error('[SMS Send Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to process SMS dispatch.' });
  } finally {
    try {
      if (lockAcquired) await connection.query('SELECT RELEASE_LOCK(?)', [lockName]);
    } catch (releaseErr) {}
    connection.release();
  }
});

// GET /api/sms/logs
app.get('/api/sms/logs', authenticate, async (req, res) => {
  try {
    const sections = await accessibleSections(req);
    const unreadOnly = req.query.unread === 'true';
    let query = `
      SELECT n.log_id, n.lrn, n.parent_contact, n.message, n.date_sent, n.status, n.isRead, n.user_id,
             CONCAT(s.first_name, ' ', s.last_name) AS student_name, s.section
      FROM notification_logs n
      LEFT JOIN students s ON n.lrn = s.lrn`;
    const params = [];
    const conditions = [];
    if (sections !== null) {
      if (sections.length === 0) {
        return res.json({ success: true, count: 0, logs: [] });
      }
      conditions.push('s.section IN (?)');
      params.push(sections);
    }
    if (unreadOnly) {
      conditions.push('n.isRead = 0');
    }
    if (conditions.length) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY n.date_sent DESC';
    const [logs] = await db.query(query, params);
    res.json({ success: true, count: logs.length, logs });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/sms/logs/:id/read - Mark a notification as read
app.put('/api/sms/logs/:id/read', authenticate, async (req, res) => {
  try {
    const logId = parseInt(req.params.id, 10);
    if (!logId) {
      return res.status(400).json({ success: false, message: 'Invalid notification ID.' });
    }

    const sections = await accessibleSections(req);
    let query = 'UPDATE notification_logs n LEFT JOIN students s ON n.lrn = s.lrn SET n.isRead = 1 WHERE n.log_id = ?';
    const params = [logId];

    if (sections !== null) {
      if (sections.length === 0) {
        return res.status(403).json({ success: false, message: 'No sections assigned.' });
      }
      query += ' AND s.section IN (?)';
      params.push(sections);
    }

    const [result] = await db.query(query, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Notification not found or not accessible.' });
    }

    res.json({ success: true, message: 'Notification marked as read.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ============================================================================
// 5. SYSTEM AUDIT LOGS & SETTINGS
// ============================================================================

async function logSystemEvent(userName, role, action, category = 'System', severity = 'info', ip = '127.0.0.1') {
  try {
    await db.query(
      'INSERT INTO system_logs (user_name, role, action, category, severity, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?, NOW())',
      [userName, role, action, category, severity, ip || '127.0.0.1']
    );
  } catch (e) {
    console.warn('[Log Error]:', e.message);
  }
}

// GET /api/system/logs - Admin only (paginated, filterable)
app.get('/api/system/logs', authenticate, requireRole('Admin'), async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(1000, Math.max(1, parseInt(req.query.pageSize, 10) || 10));
    const category = typeof req.query.category === 'string' ? req.query.category.trim() : 'all';
    const severity = typeof req.query.severity === 'string' ? req.query.severity.trim().toLowerCase() : 'all';
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const conditions = [];
    const params = [];
    if (category && category !== 'all') { conditions.push('category = ?'); params.push(category); }
    if (severity && severity !== 'all') { conditions.push('LOWER(severity) = ?'); params.push(severity); }
    if (search) {
      conditions.push('(user_name LIKE ? OR action LIKE ? OR ip_address LIKE ? OR category LIKE ?)');
      const like = '%' + search + '%';
      params.push(like, like, like, like);
    }
    const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : '';

    const [countRows] = await db.query('SELECT COUNT(*) AS total FROM system_logs' + where, params);
    const total = Number(countRows[0]?.total || 0);
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const safePage = Math.min(page, totalPages);
    const offset = (safePage - 1) * pageSize;

    const [logs] = await db.query(
      'SELECT log_id, user_name, role, action, category, severity, ip_address, timestamp FROM system_logs' + where + ' ORDER BY timestamp DESC, log_id DESC LIMIT ? OFFSET ?',
      [...params, pageSize, offset]
    );

    const mapped = logs.map(r => ({
      logId: r.log_id,
      user: r.user_name,
      role: r.role,
      action: r.action,
      category: r.category,
      severity: String(r.severity || '').toLowerCase(),
      ip: r.ip_address,
      timestamp: r.timestamp
    }));

    const [todayRows] = await db.query("SELECT COUNT(*) AS c FROM system_logs WHERE DATE(timestamp) = CURDATE()");
    const [authRows] = await db.query("SELECT COUNT(*) AS c FROM system_logs WHERE category = 'Authentication'");
    const [alertRows] = await db.query("SELECT COUNT(*) AS c FROM system_logs WHERE LOWER(severity) IN ('warning','critical')");

    res.json({
      success: true,
      count: mapped.length,
      total,
      page: safePage,
      pageSize,
      totalPages,
      logs: mapped,
      stats: {
        total,
        today: Number(todayRows[0]?.c || 0),
        auth: Number(authRows[0]?.c || 0),
        alerts: Number(alertRows[0]?.c || 0)
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/system/logs - Admin only (clear all audit logs)
app.delete('/api/system/logs', authenticate, requireRole('Admin'), async (req, res) => {
  try {
    await db.query('DELETE FROM system_logs');
    await logSystemEvent(req.user.username || req.user.name || 'Admin', req.user.role, 'Cleared all system audit logs', 'System', 'warning', req.ip);
    res.json({ success: true, message: 'System logs cleared.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/settings
app.get('/api/settings', authenticate, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT setting_key, setting_value, description FROM settings');
    const config = {};
    
    // Filter settings based on user role
    if (isAdmin(req)) {
      // Admin: full access to all settings including raw data
      rows.forEach(r => {
        config[r.setting_key] = r.setting_key === 'sms_api_key' ? Boolean(r.setting_value) : r.setting_value;
      });
      // Add TextBee environment variable configuration status
      config.textbee_api_key_configured = Boolean(process.env.TEXTBEE_API_KEY);
      config.textbee_device_id_configured = Boolean(process.env.TEXTBEE_DEVICE_ID);
      res.json({ success: true, settings: config, raw: rows });
    } else {
      // Teacher/Other authenticated users: only school_year and safe settings
      rows.forEach(r => {
        if (r.setting_key === 'school_year') {
          config[r.setting_key] = r.setting_value;
        } else if (r.setting_key === 'sms_sender_name') {
          // Sender name is low-risk, can be shown to teachers
          config[r.setting_key] = r.setting_value;
        }
        // Skip: sms_api_key, sms_gateway_mode, absence_risk_threshold, grade_risk_threshold
      });
      // Add TextBee environment variable configuration status for teachers too
      config.textbee_api_key_configured = Boolean(process.env.TEXTBEE_API_KEY);
      config.textbee_device_id_configured = Boolean(process.env.TEXTBEE_DEVICE_ID);
      res.json({ success: true, settings: config });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/settings - Admin only
app.post('/api/settings', authenticate, requireRole('Admin'), async (req, res) => {
  const updates = req.body;
  const allowedSettings = new Set(['sms_gateway_mode', 'sms_api_key', 'sms_sender_name']);
  const invalidKey = Object.keys(updates).find(key => !allowedSettings.has(key));
  if (invalidKey) return res.status(400).json({ success: false, message: `Unsupported setting: ${invalidKey}` });
  try {
    for (const [key, value] of Object.entries(updates)) {
      await db.query(
        'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?',
        [key, String(value), String(value)]
      );
    }
    await logSystemEvent(req.user.username, req.user.role, 'Updated system and SMS gateway configurations', 'System', 'info', req.ip);
    res.json({ success: true, message: 'Settings updated successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Calculate and update quarterly grades from assessment data
// Uses the official school grading system (subject-specific WW/PT/Exam weights).
async function calculateAndUpdateQuarterlyGrades(quarter) {
  try {
    const quarterStr = `Term ${quarter}`;

    // Get all assessments for the specified quarter with grading component data
    const [assessments] = await db.query(
      'SELECT assessment_id, title, type, grading_component, max_score, section, subject, subject_classification, quarter FROM assessments WHERE quarter IN (?)',
      [termAliases(quarterStr)]
    );
    assessments.forEach(a => { a.quarter = normalizeTerm(a.quarter); });

    if (!assessments.length) {
      return { message: 'No assessments found for this quarter', updated: 0 };
    }

    // Get unique sections from assessments
    const sections = [...new Set(assessments.map(a => a.section))];

    // Get all students in those sections
    const [students] = await db.query(
      'SELECT lrn, section FROM students WHERE section IN (?)',
      [sections]
    );

    if (!students.length) {
      return { message: 'No students found in sections with assessments', updated: 0 };
    }

    const lrns = students.map(s => s.lrn);

    // Get all assessment scores for these students
    const [allScores] = await db.query(
      'SELECT assessment_id, lrn, score FROM assessment_scores WHERE lrn IN (?)',
      [lrns]
    );

    // Build score lookup: lrn -> { assessment_id -> score }
    const scoreMap = {};
    allScores.forEach(score => {
      if (!scoreMap[score.lrn]) scoreMap[score.lrn] = {};
      scoreMap[score.lrn][score.assessment_id] = Number(score.score);
    });

    const columnName = `q${quarter}`;
    let updated = 0;
    const results = [];

    for (const student of students) {
      const lrn = student.lrn;
      const studentScoreMap = scoreMap[lrn] || {};

      // Only update students who have assessment score data for this quarter
      const hasAnyScore = Object.values(studentScoreMap).some(s => s !== undefined && s !== null);
      if (!hasAnyScore) continue;

      // Determine the subject for this student (use assessment subject or student's subject hint)
      const subjectName = student.subject || assessments[0]?.subject || 'General Mathematics';

      // Authoritative grade calculation using the official grading system
      const gradeResult = GradeCalc.calculateQuarterlyGrade(
        assessments,
        quarterStr,
        subjectName,
        studentScoreMap
      );

      if (gradeResult.finalGrade === null) continue; // No data to grade

      await db.query(
        `UPDATE students SET ${columnName} = ? WHERE lrn = ?`,
        [gradeResult.finalGrade, lrn]
      );
      updated++;

      results.push({
        lrn,
        quarter: quarterStr,
        finalGrade: gradeResult.finalGrade,
        classification: gradeResult.classification,
        weights: gradeResult.weights,
        components: gradeResult.components,
      });
    }

    return {
      message: `Calculated and updated quarterly grades for ${updated} students`,
      quarter: quarterStr,
      updated,
      results
    };
  } catch (err) {
    console.error('Error calculating quarterly grades:', err);
    return { message: 'Error calculating quarterly grades', error: err.message, updated: 0 };
  }
}

// API endpoint to calculate quarterly grades
app.post('/api/grades/calculate', authenticate, async (req, res) => {
  const { quarter, term } = req.body;
  const period = term || quarter;  
  if (!period || period < 1 || period > 3) {
    return res.status(400).json({ success: false, message: 'Valid term (1-3) is required.' });
  }

  const result = await calculateAndUpdateQuarterlyGrades(period);
  res.json({ success: true, ...result });
});

// API endpoint to get calculated grade for a specific student
app.get('/api/grades/student/:lrn/:quarter', authenticate, async (req, res) => {
  const { lrn, quarter } = req.params;

  // Validate quarter parameter
  const quarterNum = parseInt(quarter, 10);
  if (!Number.isInteger(quarterNum) || quarterNum < 1 || quarterNum > 3) {
    return res.status(400).json({ success: false, message: 'Valid term (1-3) is required.' });
  }

  try {
    // Get student info
    const [students] = await db.query('SELECT * FROM students WHERE lrn = ?', [lrn]);
    if (!students.length) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }

    const student = students[0];

    // Verify the requesting user has access to this student
    if (!(await canAccessStudent(req, student))) {
      return res.status(403).json({ success: false, message: 'You are not authorized to access this student.' });
    }

    const quarterStr = `Term ${quarter}`;

    // Get assessments for the quarter with grading component data
    const [assessments] = await db.query(
      'SELECT assessment_id, title, type, grading_component, max_score, section, subject, subject_classification, quarter FROM assessments WHERE quarter IN (?)',
      [termAliases(quarterStr)]
    );
    assessments.forEach(a => { a.quarter = normalizeTerm(a.quarter); });

    // Get assessment scores for this student
    let scores = [];
    if (assessments.length > 0) {
      const assessmentIds = assessments.map(a => a.assessment_id);
      const [scoreRows] = await db.query(
        'SELECT assessment_id, lrn, score FROM assessment_scores WHERE lrn = ? AND assessment_id IN (?)',
        [lrn, assessmentIds]
      );
      scores = scoreRows;
    }

    // Build score map: assessment_id -> score
    const scoreMap = {};
    scores.forEach(row => { scoreMap[row.assessment_id] = Number(row.score); });

    // Determine subject for weight lookup
    const subjectName = assessments[0]?.subject || 'General Mathematics';

    // Authoritative grade calculation using the official grading system
    const gradeResult = GradeCalc.calculateQuarterlyGrade(
      assessments,
      quarterStr,
      subjectName,
      scoreMap
    );

    // Per-assessment details for the response
    const assessmentDetails = assessments.map(assessment => {
      const norm = GradeCalc.normalizeAssessment(assessment);
      const scoreEntry = scores.find(s => s.assessment_id === assessment.assessment_id);
      const earned = scoreEntry ? Math.max(0, Number(scoreEntry.score)) : null;
      return {
        assessment_id: assessment.assessment_id,
        title: assessment.title,
        type: assessment.type,
        gradingComponent: norm.component || GradeCalc.typeToComponent(assessment.type),
        maxScore: Math.max(0, Number(assessment.max_score || 0)),
        earnedScore: earned,
        component: norm.component || GradeCalc.typeToComponent(assessment.type),
        hasScore: earned !== null && !Number.isNaN(earned),
      };
    });

    // Get the stored grade from the student record
    const storedGrade = student[`q${quarter}`] === null || student[`q${quarter}`] === undefined ? null : Number(student[`q${quarter}`]);

    res.json({
      success: true,
      quarter: quarterStr,
      lrn: student.lrn,
      studentName: `${student.first_name} ${student.last_name}`,
      section: student.section,
      subject: subjectName,
      classification: gradeResult.classification,
      weights: gradeResult.weights,
      storedQuarterlyGrade: storedGrade,
      calculatedQuarterlyGrade: gradeResult.finalGrade,
      components: gradeResult.components,
      hasAnyData: gradeResult.hasAnyData,
      assessments: assessmentDetails,
      hasAssessmentData: assessments.length > 0,
      hasScoreData: scores.length > 0
    });
  } catch (err) {
    console.error('[Grade Lookup Error]:', err);
    res.status(500).json({ success: false, message: 'Failed to retrieve student grade.' });
  }
});

// ===========================================================================
// Server Startup
// ===========================================================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`========================================================`);
  console.log(`   BINHS Early Warning System Server Running!`);
  console.log(`   URL: http://0.0.0.0:${PORT}`);
  console.log(`   Database: MySQL (${process.env.DB_NAME || 'binhs_db'})`);
  console.log(`   ML Algorithm: DecisionTreeClassifier (JavaScript)`);
  console.log(`========================================================`);
});


