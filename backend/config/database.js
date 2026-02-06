// ============================================
// DATABASE CONNECTION
// File: backend/config/database.js
// Purpose: MySQL connection pool configuration
// ============================================

const mysql = require('mysql2/promise');
require('dotenv').config();

// Create connection pool for better performance
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '11100423',
    database: process.env.DB_NAME || 'feedback_system',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

// Test database connection on startup
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✓ Database connected successfully');
        console.log(`  Database: ${process.env.DB_NAME}`);
        console.log(`  Host: ${process.env.DB_HOST}`);
        connection.release();
    } catch (err) {
        console.error('✗ Database connection failed:');
        console.error(`  Error: ${err.message}`);
        process.exit(1);
    }
})();

// Helper function to execute queries (NO recursion)
async function query(sql, params = []) {
    try {
        const [results] = await pool.execute(sql, params);
        return results;
    } catch (error) {
        console.error('Database Query Error:', error);
        throw error; // ❗ Important: do NOT retry here
    }
}

// Export pool and query helper cleanly
module.exports = {
    pool,
    query
};
