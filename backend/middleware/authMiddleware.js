const jwt = require('jsonwebtoken');
const db = require('../config/database');

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access token required'
            });
        }

        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid or expired token'
                });
            }

            const [users] = await db.query(
                'SELECT * FROM users WHERE user_id = ? AND is_active = TRUE',
                [decoded.user_id]
            );

            if (users.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'User not found or inactive'
                });
            }

            req.user = {
                user_id: decoded.user_id,
                username: decoded.username,
                email: decoded.email,
                role: decoded.role
            };

            next();
        });

    } catch (error) {
        console.error('Auth Middleware Error:', error);
        res.status(500).json({
            success: false,
            message: 'Authentication error'
        });
    }
};

module.exports = { authenticateToken };