/**
 * BINHS Early Warning System - MySQL Database Connection Pool
 * Uses mysql2/promise for async/await queries
 */

const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'binhs_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
});

// Test connection on startup
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log(`[Database] Connected successfully to MySQL database "${process.env.DB_NAME || 'binhs_db'}" on port ${process.env.DB_PORT || 3306}`);
    connection.release();
  } catch (err) {
    console.error(`[Database Error] Could not connect to MySQL:`, err.message);
  }
})();

module.exports = pool;
