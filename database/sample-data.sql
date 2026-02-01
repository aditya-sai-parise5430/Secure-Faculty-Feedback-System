-- ============================================
-- SAMPLE TEST DATA
-- File: database/sample-data.sql
-- Purpose: Populate database with test users and courses
-- ============================================

USE feedback_system;

-- Note: For actual implementation, passwords should be hashed by the application
-- These are placeholder hashes. Use the registration endpoint to create real users.

-- ============================================
-- SAMPLE USERS
-- ============================================

-- Admin User (username: admin, password will be: Admin@123)
-- You MUST register this through the application
INSERT INTO users (username, email, password_hash, salt, role, full_name, department, is_verified) 
VALUES ('admin', 'admin@amrita.edu', 'WILL_BE_HASHED_BY_APP', 'salt1', 'admin', 
        'System Administrator', 'Computer Science', TRUE);

-- ============================================
-- SAMPLE COURSES
-- ============================================

INSERT INTO courses (course_code, course_name, department, semester, academic_year, description) VALUES
('23CSE313', 'Foundations of Cyber Security', 'Computer Science', 'Odd 2024', '2024-25', 
 'Covers authentication, encryption, access control, and security fundamentals'),
 
('23CSE301', 'Database Management Systems', 'Computer Science', 'Odd 2024', '2024-25',
 'Relational databases, SQL, normalization, and transactions'),
 
('23CSE305', 'Operating Systems', 'Computer Science', 'Odd 2024', '2024-25',
 'Process management, memory management, file systems'),
 
('23CSE307', 'Computer Networks', 'Computer Science', 'Even 2024', '2024-25',
 'Network protocols, TCP/IP, routing, and network security'),
 
('23CSE309', 'Software Engineering', 'Computer Science', 'Even 2024', '2024-25',
 'SDLC, Agile methodologies, software testing, and project management');

-- ============================================
-- NOTES FOR SETUP
-- ============================================

/*
IMPORTANT: DO NOT use these SQL inserts for creating users with passwords!

CORRECT SETUP PROCESS:
======================

1. Run this SQL file to create courses only

2. Use the APPLICATION REGISTRATION to create users:
   - Open http://localhost:5173 in browser
   - Click "Register"
   - Fill in details:
     * Admin: username=admin, email=admin@amrita.edu, role=admin
     * Faculty: username=faculty1, email=faculty@amrita.edu, role=faculty
     * Student: username=student1, email=student@amrita.edu, role=student
   - System will hash password properly and send OTP
   - Verify OTP to complete registration

3. After registration, log in as admin to:
   - Assign faculty to courses
   - Manage system settings
   - View analytics

4. Log in as faculty to:
   - Assign courses (or wait for admin assignment)
   - View feedback for assigned courses

5. Log in as student to:
   - Submit anonymous feedback for courses

LOGIN CREDENTIALS (after you register):
========================================
Admin:   admin / Admin@123
Faculty: faculty1 / Faculty@123  
Student: student1 / Student@123

(Set whatever passwords you want during registration)
*/

SELECT 'Sample data loaded! Now register users through the application.' as Status;