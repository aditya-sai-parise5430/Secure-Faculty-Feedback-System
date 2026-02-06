// ============================================
// FILE: backend/routes/feedbackRoutes.js
// Purpose: Routes for anonymous feedback system
// ============================================

const express = require('express');
const router = express.Router();

const FeedbackController = require('../controllers/feedbackController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { authorizeRole } = require('../middleware/accessControl');

// ============================================
// STUDENT ROUTES
// ============================================

// Student submits anonymous feedback
router.post(
    '/',
    authenticateToken,
    authorizeRole('student'),
    FeedbackController.submitFeedback
);

// ============================================
// STUDENT: View faculty list
// ============================================
router.get(
    '/faculty',
    authenticateToken,
    authorizeRole('student'),
    FeedbackController.getFacultyList
);


// ============================================
// FACULTY ROUTES
// ============================================

// Faculty views their feed backs
router.get(
    '/my',
    authenticateToken,
    authorizeRole('faculty'),
    FeedbackController.getMyFeedback
);

// Faculty generates their unique QR code
router.get(
    '/qr',
    authenticateToken,
    authorizeRole('faculty'),
    FeedbackController.generateQRCode
);

// ============================================
// ADMIN ROUTES
// ============================================
// ... existing imports

// ADMIN: Get grouped dashboard data
// Ensure this specific route is ABOVE any generic /:id routes if you add them later
router.get(
    '/admin/dashboard',
    authenticateToken,
    authorizeRole('admin'),
    FeedbackController.getAdminDashboard
);

router.delete(
    '/admin/:feedback_id',
    authenticateToken,
    authorizeRole('admin'),
    FeedbackController.deleteFeedback
);

module.exports = router;
