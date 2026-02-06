// ============================================
// FILE: backend/controllers/authController.js
// COMPONENT 1: Authentication (Single & Multi-Factor)
// ============================================

const db = require('../config/database');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { HashingService, OTPService } = require('../utils/cryptoUtils');
const { sendOTPEmail, sendWelcomeEmail } = require('../utils/emailService');
const { logAuditEvent } = require('../middleware/accessControl');

class AuthController {

    // ============================================
    // USER REGISTRATION (with OTP verification)
    // ============================================
    static async register(req, res) {
        const { username, email, password, role, full_name, department, phone } = req.body;
        try {
            

            if (!username || !email || !password || !role || !full_name) {
                return res.status(400).json({
                    success: false,
                    message: 'All required fields must be provided'
                });
            }

            if (password.length < 8) {
                return res.status(400).json({
                    success: false,
                    message: 'Password must be at least 8 characters long'
                });
            }

            // Check existing user
            const existingUsers = await db.query(
                'SELECT user_id FROM users WHERE username = ? OR email = ?',
                [username, email]
            );

            if (existingUsers.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Username or email already exists'
                });
            }

            // Hash password
            const { hash, salt } = await HashingService.hashPassword(password);

            // Insert user
            const result = await db.query(`
                INSERT INTO users
                (username, email, password_hash, salt, role, full_name, department, phone, is_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE)
            `, [username, email, hash, salt, role, full_name, department || null, phone || null]);

            const userId = result.insertId;

            // Generate OTP
            const otp = OTPService.generateOTP(6);
            const otpHash = await OTPService.hashOTP(otp);
            const expiresAt = OTPService.calculateExpiry(10);

            await db.query(`
                INSERT INTO otp_tokens (user_id, otp_code, otp_hash, purpose, expires_at)
                VALUES (?, ?, ?, 'registration', ?)
            `, [userId, otp, otpHash, expiresAt]);
            

            // Send OTP email
            await sendOTPEmail(email, otp, 'registration');

            await logAuditEvent(
                userId,
                'User registration initiated',
                'user',
                userId,
                'success',
                req.ip,
                req.get('user-agent')
            );

            res.status(201).json({
                success: true,
                message: 'Registration successful! Please check your email for OTP verification.',
                user_id: userId,
                requires_verification: true
            });

        } catch (error) {
            console.error('Registration Error:', error);
        
            // 🔴 IMPORTANT FIX:
            // If registration fails after user insert (OTP/email failure),
            // remove the partially created unverified user
            if (email) {
                await db.query(
                    'DELETE FROM users WHERE email = ? AND is_verified = FALSE',
                    [email]
                );
            }
        
            res.status(500).json({
                success: false,
                message: 'Registration failed. Please try again.'
            });
        }
        
    }

    // ============================================
    // VERIFY REGISTRATION OTP
    // ============================================
    static async verifyRegistration(req, res) {
        try {
            const { user_id, otp } = req.body;

            const otpRecords = await db.query(`
                SELECT * FROM otp_tokens
                WHERE user_id = ? AND purpose = 'registration' AND is_used = FALSE
                ORDER BY created_at DESC LIMIT 1
            `, [user_id]);

            if (otpRecords.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid or expired OTP'
                });
            }

            const otpRecord = otpRecords[0];

            if (OTPService.isExpired(otpRecord.expires_at)) {
                return res.status(400).json({
                    success: false,
                    message: 'OTP has expired'
                });
            }

            const validOTP = await OTPService.verifyOTP(otp, otpRecord.otp_hash);

            if (!validOTP) {
                return res.status(401).json({
                    success: false,
                    message: 'Incorrect OTP'
                });
            }

            // Mark OTP as used
            await db.query(
                'UPDATE otp_tokens SET is_used = TRUE WHERE otp_id = ?',
                [otpRecord.otp_id]
            );

            // Verify user
            await db.query(
                'UPDATE users SET is_verified = TRUE WHERE user_id = ?',
                [user_id]
            );

            const users = await db.query(
                'SELECT * FROM users WHERE user_id = ?',
                [user_id]
            );

            const user = users[0];

            await sendWelcomeEmail(user.email, user.full_name, user.role);

            await logAuditEvent(
                user_id,
                'Email verified successfully',
                'user',
                user_id,
                'success',
                req.ip,
                req.get('user-agent')
            );

            res.status(200).json({
                success: true,
                message: 'Email verified successfully! You can now log in.'
            });

        } catch (error) {
            console.error('OTP Verification Error:', error);
            res.status(500).json({
                success: false,
                message: 'OTP verification failed'
            });
        }
    }

    // ============================================
    // LOGIN (Single-factor or MFA)
    // ============================================
    static async login(req, res) {
        try {
            const { username, password } = req.body;

            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Username and password are required'
                });
            }

            const users = await db.query(`
                SELECT * FROM users
                WHERE (username = ? OR email = ?) AND is_verified = TRUE
            `, [username, username]);

            if (users.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials or account not verified'
                });
            }

            const user = users[0];

            const validPassword = await HashingService.verifyPassword(
                password,
                user.password_hash
            );

            if (!validPassword) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            // Check MFA
            const mfaConfig = await db.query(
                'SELECT * FROM mfa_config WHERE user_id = ? AND is_enabled = TRUE',
                [user.user_id]
            );

            if (mfaConfig.length > 0) {
                const otp = OTPService.generateOTP(6);
                const otpHash = await OTPService.hashOTP(otp);
                const expiresAt = OTPService.calculateExpiry(10);

                await db.query(`
                    INSERT INTO otp_tokens (user_id, otp_hash, purpose, expires_at)
                    VALUES (?, ?, 'login', ?)
                `, [user.user_id, otpHash, expiresAt]);

                await sendOTPEmail(user.email, otp, 'login');

                const tempToken = jwt.sign(
                    { user_id: user.user_id, stage: 'mfa_pending' },
                    process.env.JWT_SECRET,
                    { expiresIn: '10m' }
                );

                return res.json({
                    success: true,
                    requires_mfa: true,
                    temp_token: tempToken,
                    message: 'OTP sent for MFA verification'
                });
            }

            return AuthController.completeLogin(user, req, res);

        } catch (error) {
            console.error('Login Error:', error);
            res.status(500).json({
                success: false,
                message: 'Login failed'
            });
        }
    }

    // ============================================
    // VERIFY MFA OTP
    // ============================================
    static async verifyMFA(req, res) {
        try {
            const { temp_token, otp } = req.body;

            const decoded = jwt.verify(temp_token, process.env.JWT_SECRET);

            const otpRecords = await db.query(`
                SELECT * FROM otp_tokens
                WHERE user_id = ? AND purpose = 'login' AND is_used = FALSE
                ORDER BY created_at DESC LIMIT 1
            `, [decoded.user_id]);

            if (otpRecords.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'OTP not found'
                });
            }

            const otpRecord = otpRecords[0];

            const validOTP = await OTPService.verifyOTP(otp, otpRecord.otp_hash);

            if (!validOTP) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid OTP'
                });
            }

            await db.query(
                'UPDATE otp_tokens SET is_used = TRUE WHERE otp_id = ?',
                [otpRecord.otp_id]
            );

            const users = await db.query(
                'SELECT * FROM users WHERE user_id = ?',
                [decoded.user_id]
            );

            return AuthController.completeLogin(users[0], req, res);

        } catch (error) {
            console.error('MFA Error:', error);
            res.status(500).json({
                success: false,
                message: 'MFA verification failed'
            });
        }
    }

    // ============================================
    // COMPLETE LOGIN
    // ============================================
    static async completeLogin(user, req, res) {
        const token = jwt.sign(
            {
                user_id: user.user_id,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        const sessionId = crypto.randomBytes(32).toString('hex');
        const sessionHash = HashingService.hashData(token);

        await db.query(`
            INSERT INTO sessions (session_id, user_id, session_token_hash, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))
        `, [sessionId, user.user_id, sessionHash, req.ip, req.get('user-agent')]);

        res.json({
            success: true,
            token,
            session_id: sessionId,
            user: {
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                role: user.role,
                full_name: user.full_name
            }
        });
    }
}

module.exports = AuthController;
