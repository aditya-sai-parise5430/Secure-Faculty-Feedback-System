// ============================================
// EMAIL SERVICE
// File: backend/utils/emailService.js
// Purpose: Send emails for OTP, notifications
// ============================================

const nodemailer = require('nodemailer');
require('dotenv').config();

// Create email transporter
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Verify transporter configuration
transporter.verify(function (error, success) {
    if (error) {
        console.log('✗ Email configuration error:', error.message);
        console.log('  Check EMAIL_* settings in .env file');
    } else {
        console.log('✓ Email service ready');
    }
});



/**
 * Generic email sending function
 */
async function sendEmail(to, subject, text, html = null) {
    try {
        const mailOptions = {
            from: `"Secure Feedback System" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
            to,
            subject,
            text,
            html: html || text
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('✓ Email sent:', info.messageId);
        return { success: true, messageId: info.messageId };

    } catch (error) {
        console.error('✗ Email sending failed:', error.message);
        return { success: false, error: error.message };
    }
}

/**
 * Send OTP email for registration/login
 */
async function sendOTPEmail(to, otp, purpose = 'verification') {
    const subject = `Your OTP for ${purpose}`;
    
    const html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border: 1px solid #ddd; }
        .otp-box { background: white; border: 3px dashed #667eea; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px; }
        .otp { font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .security-tips { background: #e7f3ff; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Secure Feedback System</h1>
            <p>Multi-Factor Authentication</p>
        </div>
        
        <div class="content">
            <h2>Your One-Time Password</h2>
            <p>Hello! You requested a verification code for ${purpose}.</p>
            
            <div class="otp-box">
                <p style="margin: 0; font-size: 14px; color: #666;">Your OTP is:</p>
                <div class="otp">${otp}</div>
            </div>
            
            <div class="warning">
                <strong>⚠️ Important:</strong>
                <ul style="margin: 10px 0;">
                    <li>This OTP is valid for <strong>10 minutes</strong></li>
                    <li>Do not share this code with anyone</li>
                    <li>We will never ask for your OTP via phone or email</li>
                </ul>
            </div>
            
            <div class="security-tips">
                <strong>🛡️ Security Tips:</strong>
                <ul style="margin: 10px 0;">
                    <li>Check that the URL starts with https://</li>
                    <li>Never enter OTP on suspicious websites</li>
                    <li>Log out after completing your session</li>
                </ul>
            </div>
            
            <p style="color: #666; font-size: 14px; margin-top: 20px;">
                If you didn't request this code, please ignore this email and ensure your account is secure.
            </p>
        </div>
        
        <div class="footer">
            <p>Secure Faculty Feedback & Review System</p>
            <p>Amrita Vishwa Vidyapeetham</p>
            <p style="font-size: 10px; margin-top: 10px;">
                This is an automated email. Please do not reply.
            </p>
        </div>
    </div>
</body>
</html>
    `;

    return await sendEmail(to, subject, `Your OTP is: ${otp}`, html);
}

/**
 * Send welcome email after successful registration
 */
async function sendWelcomeEmail(to, fullName, role) {
    const subject = 'Welcome to Secure Feedback System';
    
    const html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border: 1px solid #ddd; }
        .features { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .feature-item { padding: 10px; margin: 10px 0; border-left: 4px solid #667eea; padding-left: 15px; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome to Secure Feedback System!</h1>
        </div>
        
        <div class="content">
            <h2>Hello ${fullName}!</h2>
            <p>Your account has been successfully created with the role of <strong>${role}</strong>.</p>
            
            <div class="features">
                <h3>🔐 Security Features:</h3>
                <div class="feature-item">
                    <strong>Multi-Factor Authentication:</strong> Extra layer of security with OTP
                </div>
                <div class="feature-item">
                    <strong>End-to-End Encryption:</strong> Your feedback is encrypted with AES-256
                </div>
                <div class="feature-item">
                    <strong>Anonymous Feedback:</strong> Student identity protected
                </div>
                <div class="feature-item">
                    <strong>Digital Signatures:</strong> Data integrity guaranteed
                </div>
            </div>
            
            ${role === 'student' ? `
            <p><strong>As a Student, you can:</strong></p>
            <ul>
                <li>Submit anonymous feedback for faculty</li>
                <li>Rate faculty on a scale of 1-10</li>
                <li>Your identity remains completely protected</li>
            </ul>
            ` : ''}
            
            ${role === 'faculty' ? `
            <p><strong>As Faculty, you can:</strong></p>
            <ul>
                <li>View feedback form your students</li>
                <li>Access analytics and statistics</li>
                <li>All feedback is anonymous</li>
            </ul>
            ` : ''}
            
            ${role === 'admin' ? `
            <p><strong>As Admin, you can:</strong></p>
            <ul>
                <li>Manage all system users</li>
                <li>Generate QR codes for feedback</li>
                <li>View comprehensive analytics</li>
            </ul>
            ` : ''}
            
            <p style="margin-top: 30px;">
                <strong>Next Steps:</strong><br>
                Log in to the system and explore all features!
            </p>
        </div>
        
        <div class="footer">
            <p>Secure Faculty Feedback & Review System</p>
            <p>Amrita Vishwa Vidyapeetham - Computer Science Department</p>
        </div>
    </div>
</body>
</html>
    `;

    return await sendEmail(to, subject, `Welcome ${fullName}!`, html);
}

/**
 * Send password reset email
 */
async function sendPasswordResetEmail(to, resetToken) {
    const subject = 'Password Reset Request';
    
    const html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border: 1px solid #ddd; }
        .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔑 Password Reset</h1>
        </div>
        
        <div class="content">
            <h2>Reset Your Password</h2>
            <p>We received a request to reset your password.</p>
            
            <p>Your password reset token:</p>
            <div style="background: white; padding: 15px; border: 2px solid #667eea; text-align: center; font-size: 20px; letter-spacing: 2px; margin: 20px 0;">
                ${resetToken}
            </div>
            
            <div class="warning">
                <strong>⚠️ Security Notice:</strong>
                <ul>
                    <li>This token expires in 15 minutes</li>
                    <li>If you didn't request this, ignore this email</li>
                    <li>Never share this token with anyone</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
    `;

    return await sendEmail(to, subject, `Password reset token: ${resetToken}`, html);
}

// Export all email functions
module.exports = {
    sendEmail,
    sendOTPEmail,
    sendWelcomeEmail,
    sendPasswordResetEmail
};