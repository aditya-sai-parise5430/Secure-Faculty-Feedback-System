// ============================================
// FILE: backend/routes/authRoutes.js
// ============================================

const express = require('express');
const router = express.Router();

const AuthController = require('../controllers/authController');

// Registration
router.post('/register', AuthController.register);
router.post('/verify-registration', AuthController.verifyRegistration);

// Login + MFA
router.post('/login', AuthController.login);
router.post('/verify-mfa', AuthController.verifyMFA);

module.exports = router;
