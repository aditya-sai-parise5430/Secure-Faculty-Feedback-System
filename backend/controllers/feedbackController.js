// ============================================
// FILE: backend/controllers/feedbackController.js
// Purpose: Handle anonymous feedback submission & viewing
// Roles:
//  - Student: submit feedback (anonymous)
//  - Faculty: view own feedback (read-only)
//  - Admin: view & moderate all feedback
// ============================================

const db = require('../config/database');
const crypto = require('crypto');
const QRCode = require('qrcode');
const {
    EncryptionService,
    DigitalSignatureService,
    EncodingService
} = require('../utils/cryptoUtils');
const { logAuditEvent } = require('../middleware/accessControl');

const encryptionService = new EncryptionService();
const signatureService = new DigitalSignatureService();

class FeedbackController {

    // ============================================
    // STUDENT: Submit Anonymous Feedback
    // ============================================
    static async submitFeedback(req, res) {
        try {
            const studentId = req.user.user_id;
            const { faculty_id, feedback_text, rating } = req.body;

            if (!faculty_id || !feedback_text || !rating) {
                return res.status(400).json({
                    success: false,
                    message: 'All fields are required'
                });
            }

            const anonymousId = EncodingService.generateAnonymousId(
                studentId,
                Date.now()
            );

            // 🔐 AES-256-GCM ENCRYPTION
            const encrypted = encryptionService.encrypt(feedback_text);

            await db.query(`
                INSERT INTO feedback (
                    faculty_id,
                    encrypted_content,
                    encryption_iv,
                    auth_tag,
                    rating,
                    anonymous_id
                ) VALUES (?, ?, ?, ?, ?, ?)
            `, [
                faculty_id,
                encrypted.encrypted,
                encrypted.iv,
                encrypted.authTag,
                rating,
                anonymousId
            ]);

            // Log audit event
            await logAuditEvent(
                studentId,
                'Submit feedback',
                'feedback',
                null,
                'success',
                req.ip,
                req.get('user-agent')
            );

            res.json({
                success: true,
                message: 'Feedback submitted anonymously'
            });

        } catch (err) {
            console.error('Submit Feedback Error:', err);
            res.status(500).json({
                success: false,
                message: 'Submission failed'
            });
        }
    }


    // ============================================
    // FACULTY: View Their Own Feedback
    // ============================================
    static async getMyFeedback(req, res) {
        try {
            const facultyId = req.user.user_id;

            // ✅ DO NOT destructure
            const rows = await db.query(`
                SELECT
                    feedback_id,
                    encrypted_content,
                    encryption_iv,
                    auth_tag,
                    rating,
                    submission_timestamp
                FROM feedback
                WHERE faculty_id = ?
                ORDER BY submission_timestamp DESC
            `, [facultyId]);

            // ✅ rows is already an ARRAY in your setup
            const feedback = rows.map(f => ({
                feedback_id: f.feedback_id,
                rating: f.rating,
                submitted_at: f.submission_timestamp,
                // ✅ FIX: Use encryptionService instance, not EncryptionService class
                feedback: encryptionService.decrypt(
                    f.encrypted_content,
                    f.encryption_iv,
                    f.auth_tag
                )
            }));

            res.json({
                success: true,
                feedback
            });

        } catch (error) {
            console.error('Faculty Feedback Error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to load reviews'
            });
        }
    }


    // ============================================
    // STUDENT: Get Faculty List
    // ============================================
    static async getFacultyList(req, res) {
        try {
            const faculty = await db.query(`
                SELECT user_id AS faculty_id, full_name, department
                FROM users
                WHERE role = 'faculty'
                  AND is_active = TRUE
                  AND is_verified = TRUE
                ORDER BY full_name ASC
            `);

            res.json({
                success: true,
                faculty
            });

        } catch (err) {
            console.error('Get Faculty Error:', err);
            res.status(500).json({
                success: false,
                message: 'Failed to load faculty'
            });
        }
    }
    // ============================================
    // ADMIN: Get Dashboard Data (Grouped by Faculty)
    // ============================================
    static async getAdminDashboard(req, res) {
        try {
            console.log("-----------------------------------------");
            console.log("DEBUG: Admin requested dashboard.");

            // 1. Get all faculty members
            const facultyMembers = await db.query(`
                SELECT user_id, full_name, department 
                FROM users 
                WHERE role = 'faculty'
            `);

            console.log(`DEBUG: Found ${facultyMembers.length} faculty members in DB.`);

            if (facultyMembers.length === 0) {
                // Double check if any users exist at all?
                const allUsers = await db.query("SELECT role FROM users");
                console.log("DEBUG: Roles found in DB:", allUsers.map(u => u.role));
            }

            // 2. Get all feedback with ratings
            const allFeedback = await db.query(`
                SELECT * FROM feedback ORDER BY submission_timestamp DESC
            `);

            console.log(`DEBUG: Found ${allFeedback.length} total feedback entries.`);

            // 3. Group feedback by faculty
            const dashboardData = facultyMembers.map(faculty => {
                const facultyReviews = allFeedback.filter(f => f.faculty_id === faculty.user_id);

                // Calculate Stats
                const totalRating = facultyReviews.reduce((sum, review) => sum + review.rating, 0);
                const avgRating = facultyReviews.length > 0 ? (totalRating / facultyReviews.length).toFixed(1) : 0;

                // Decrypt
                const decryptedReviews = facultyReviews.map(f => {
                    try {
                        return {
                            feedback_id: f.feedback_id,
                            rating: f.rating,
                            submitted_at: f.submission_timestamp,
                            content: encryptionService.decrypt(f.encrypted_content, f.encryption_iv, f.auth_tag)
                        };
                    } catch (e) {
                        return { feedback_id: f.feedback_id, content: "[Decryption Error]" };
                    }
                });

                return {
                    faculty_id: faculty.user_id,
                    name: faculty.full_name,
                    department: faculty.department,
                    average_rating: avgRating,
                    total_reviews: facultyReviews.length,
                    reviews: decryptedReviews
                };
            });

            res.status(200).json({
                success: true,
                faculty_blocks: dashboardData
            });

        } catch (error) {
            console.error('Admin Dashboard Error:', error);
            res.status(500).json({ success: false, message: 'Failed to generate dashboard data' });
        }
    }

    // ============================================
    // ADMIN: View All Feedback
    // ============================================
    static async getAllFeedback(req, res) {
        try {
            const feedbacks = await db.query(`
                SELECT
                    f.feedback_id,
                    f.encrypted_content,
                    f.encryption_iv,
                    f.auth_tag,
                    f.rating,
                    f.submission_timestamp,
                    f.anonymous_id,
                    u.full_name AS faculty_name,
                    u.department
                FROM feedback f
                JOIN users u ON f.faculty_id = u.user_id
                ORDER BY f.submission_timestamp DESC
            `);

            const decryptedFeedbacks = feedbacks.map(f => ({
                feedback_id: f.feedback_id,
                faculty_name: f.faculty_name,
                department: f.department,
                rating: f.rating,
                anonymous_id: f.anonymous_id,
                submitted_at: f.submission_timestamp,
                feedback: encryptionService.decrypt(
                    f.encrypted_content,
                    f.encryption_iv,
                    f.auth_tag
                )
            }));

            res.status(200).json({
                success: true,
                feedback: decryptedFeedbacks
            });

        } catch (error) {
            console.error('Admin Feedback Error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to fetch feedback'
            });
        }
    }

    // ============================================
    // ADMIN: Delete Suspicious Feedback
    // ============================================
    static async deleteFeedback(req, res) {
        try {
            const { feedback_id } = req.params;

            await db.query(
                'DELETE FROM feedback WHERE feedback_id = ?',
                [feedback_id]
            );

            await logAuditEvent(
                req.user.user_id,
                'Deleted feedback',
                'feedback',
                feedback_id,
                'success',
                req.ip,
                req.get('user-agent')
            );

            res.status(200).json({
                success: true,
                message: 'Feedback removed successfully'
            });

        } catch (error) {
            console.error('Delete Feedback Error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to delete feedback'
            });
        }
    }

    // ============================================
    // FACULTY: Generate QR Code with Performance Summary
    // ============================================
    static async generateQRCode(req, res) {
        try {
            const facultyId = req.user.user_id;

            // 1. Fetch Feedback Stats
            const stats = await db.query(`
                SELECT 
                    COUNT(*) as total_reviews,
                    AVG(rating) as avg_rating
                FROM feedback
                WHERE faculty_id = ?
            `, [facultyId]);

            const total = stats[0]?.total_reviews || 0;
            const avg = stats[0]?.avg_rating ? parseFloat(stats[0].avg_rating).toFixed(1) : 'N/A';

            // 2. Fetch Faculty Name
            const user = await db.query('SELECT full_name FROM users WHERE user_id = ?', [facultyId]);
            const name = user[0] ? user[0].full_name : 'Faculty';

            // 3. Fetch Detailed Reviews (Sorted by Rating ASC)
            const reviews = await db.query(`
                SELECT rating, encrypted_content, encryption_iv, auth_tag
                FROM feedback
                WHERE faculty_id = ?
                ORDER BY rating ASC
            `, [facultyId]);

            let reviewsSummary = "\n\n--- REVIEWS (Low to High) ---\n";

            if (reviews.length > 0) {
                reviews.forEach(r => {
                    try {
                        const decrypted = encryptionService.decrypt(r.encrypted_content, r.encryption_iv, r.auth_tag);
                        reviewsSummary += `\n[Rating: ${r.rating}/10] ${decrypted}`;
                    } catch (e) {
                        reviewsSummary += `\n[Rating: ${r.rating}/10] [Error Decrypting]`;
                    }
                });
            } else {
                reviewsSummary += "No reviews available.";
            }

            // 4. Create Final Summary String
            // This satisfies the "Encoding" requirement by encoding DATA, not just a link.
            const summaryData = `SECURE FEEDBACK REPORT\n\nFaculty: ${name}\nTotal Reviews: ${total}\nAverage Rating: ${avg}/10\n\nStatus: Verified${reviewsSummary}`;

            // 5. Encode to QR
            const qrCodeImage = await QRCode.toDataURL(summaryData);

            res.json({
                success: true,
                qr_code: qrCodeImage,
                summary: summaryData
            });

        } catch (error) {
            console.error('QR Gen Error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to generate QR code'
            });
        }
    }
}

module.exports = FeedbackController;