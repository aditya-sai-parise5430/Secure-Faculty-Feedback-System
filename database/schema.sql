DROP DATABASE IF EXISTS feedback_system;
CREATE DATABASE feedback_system;
USE feedback_system;

-- ============================================
-- USERS
-- ============================================
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    role ENUM('student','faculty','admin') NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    department VARCHAR(50),
    phone VARCHAR(15),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================
-- FEEDBACK (Consolidated & Safe Sizes)
-- ============================================
CREATE TABLE feedback (
    feedback_id INT PRIMARY KEY AUTO_INCREMENT,
    faculty_id INT NOT NULL,
    encrypted_content TEXT NOT NULL,
    -- Increased to 64 to prevent truncation of crypto data
    encryption_iv VARCHAR(64) NOT NULL, 
    auth_tag VARCHAR(64) NOT NULL,
    rating INT CHECK (rating BETWEEN 1 AND 10),
    anonymous_id VARCHAR(64) NOT NULL,
    submission_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (faculty_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- OTHER TABLES (Keep as they are)
-- ============================================
CREATE TABLE otp_tokens (
    otp_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    purpose ENUM('login','registration','password_reset') NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    session_token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE audit_log (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NULL,
    action VARCHAR(100),
    resource_type VARCHAR(50),
    resource_id INT NULL,
    action_result ENUM('success','failure','unauthorized'),
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE  mfa_config (
    mfa_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    mfa_secret VARCHAR(255) NOT NULL,
    mfa_type ENUM('email_otp','totp','sms') NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- SYSTEM SETTINGS
-- ============================================
CREATE TABLE system_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT
);

INSERT INTO system_settings VALUES ('feedback_enabled','true');