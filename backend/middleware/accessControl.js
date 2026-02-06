// ============================================
// ACCESS CONTROL MIDDLEWARE
// File: backend/middleware/accessControl.js
// Purpose: COMPONENT 2 - Authorization & Access Control
// Implements: ACL, Access Control Matrix, Permission Checks
// ============================================

const db = require('../config/database');

// ============================================
// ACCESS CONTROL MATRIX DEFINITION
// COMPONENT 2.1: 3+ Subjects, 5+ Objects
// ============================================

/**
 * Permissions: R=Read, W=Write, D=Delete, E=Execute, G=Grant
 * R* = Read only own/assigned resources
 * 
 * MATRIX:
 * +-----------+----------+--------+------+--------+-----------------+
 * | Subject   | Feedback | Course | User | Report | System_Settings |
 * +-----------+----------+--------+------+--------+-----------------+
 * | Student   | W        | R      | R*   | -      | -               |
 * | Faculty   | R*       | R*     | R*   | R*     | -               |
 * | Admin     | RWDEG    | RWDEG  | RWDEG| RWDEG  | RWDEG           |
 * +-----------+----------+--------+------+--------+-----------------+
 */

const AccessControlMatrix = {
    student: {
        feedback: ['write']
    },
    faculty: {
        feedback: ['read_own']
    },
    admin: {
        feedback: ['read', 'delete']
    }
};

// ============================================
// POLICY DEFINITIONS & JUSTIFICATIONS
// COMPONENT 2.2: Clear policy definitions
// ============================================

const PolicyDocumentation = {
    student: {
        feedback_write: {
            permission: 'WRITE access to Feedback',
            justification: 'Students need to submit feedback anonymously for courses',
            security: 'Anonymous submission protects student identity'
        },
        
        user_read_own: {
            permission: 'READ access to own User profile only',
            justification: 'Students can view and update their own profile',
            security: 'Cannot access other students data, maintains privacy'
        }
    },
    faculty: {
        feedback_read_assigned: {
            permission: 'READ access to Feedback for assigned courses only',
            justification: 'Faculty need to read feedback for courses they teach',
            security: 'Need-to-know basis, cannot access other faculty feedback'
        },
        
        report_read_assigned: {
            permission: 'READ access to Reports for their courses',
            justification: 'Faculty need analytics for performance evaluation',
            security: 'Aggregated data maintains student anonymity'
        }
    },
    admin: {
        all_access: {
            permission: 'Full access (RWDEG) to all resources',
            justification: 'Admins need complete system management capabilities',
            security: 'All actions logged in audit trail, limited admin accounts'
        },
        grant_permissions: {
            permission: 'GRANT permission capability',
            justification: 'Admins can delegate responsibilities and assign roles',
            security: 'All grants logged with grantor information'
        }
    }
};

// ============================================
// ACL MANAGER CLASS
// ============================================

class ACLManager {
    /**
     * Check if subject has permission on object
     * COMPONENT 2.3: Programmatic enforcement
     */
    

    /**
     * Check if faculty is assigned to a course/feedback
     */
    
    /**
     * Grant permission (only admin can grant)
     */
    static async grantPermission(grantedBy, subjectType, subjectId, objectType, objectId, permissions, expiresAt = null) {
        try {
            const permissionFields = {
                permission_read: permissions.includes('read'),
                permission_write: permissions.includes('write'),
                permission_delete: permissions.includes('delete'),
                permission_execute: permissions.includes('execute'),
                permission_grant: permissions.includes('grant')
            };

            const [result] = await db.query(`
                INSERT INTO access_control 
                (subject_type, subject_id, object_type, object_id, 
                 permission_read, permission_write, permission_delete, 
                 permission_execute, permission_grant, granted_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                subjectType, subjectId, objectType, objectId,
                permissionFields.permission_read,
                permissionFields.permission_write,
                permissionFields.permission_delete,
                permissionFields.permission_execute,
                permissionFields.permission_grant,
                grantedBy,
                expiresAt
            ]);

            return result.insertId;
        } catch (error) {
            console.error('Grant Permission Error:', error);
            throw error;
        }
    }

    /**
     * Revoke permission
     */
    static async revokePermission(aclId) {
        await db.query('DELETE FROM access_control WHERE acl_id = ?', [aclId]);
    }

    /**
     * List all permissions for a subject
     */
    static async listPermissions(subjectId, subjectRole) {
        const [permissions] = await db.query(`
            SELECT * FROM access_control
            WHERE subject_type = ? AND (subject_id IS NULL OR subject_id = ?)
            AND (expires_at IS NULL OR expires_at > NOW())
        `, [subjectRole, subjectId]);

        return permissions;
    }
}

// ============================================
// MIDDLEWARE FUNCTIONS
// ============================================

/**
 * Require specific permission on object type
 */
const requirePermission = (objectType, permission) => {
    return async (req, res, next) => {
        try {
            const userId = req.user.user_id;
            const userRole = req.user.role;
            const objectId = req.params.id || req.params.course_id || req.body.id || null;


            if (!hasPermission) {
                // Log unauthorized access attempt
                await logAuditEvent(
                    userId,
                    `Unauthorized ${permission} attempt on ${objectType}`,
                    objectType,
                    objectId,
                    'unauthorized',
                    req.ip,
                    req.get('user-agent')
                );

                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Insufficient permissions.',
                    required_permission: permission,
                    object_type: objectType,
                    your_role: userRole
                });
            }

            // Permission granted, proceed
            next();

        } catch (error) {
            console.error('Permission Check Error:', error);
            res.status(500).json({
                success: false,
                message: 'Error checking permissions'
            });
        }
    };
};

/**
 * Require specific role(s)
 */
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            // Log unauthorized access
            logAuditEvent(
                req.user.user_id,
                `Unauthorized role access attempt`,
                'system',
                null,
                'unauthorized',
                req.ip,
                req.get('user-agent')
            );

            return res.status(403).json({
                success: false,
                message: 'Access denied. Insufficient role privileges.',
                required_roles: allowedRoles,
                your_role: req.user.role
            });
        }

        next();
    };
};

/**
 * Verify ownership of resource
 */
const requireOwnership = (resourceType) => {
    return async (req, res, next) => {
        try {
            const userId = req.user.user_id;
            const resourceId = req.params.id;

            // Admin bypasses ownership check
            if (req.user.role === 'admin') {
                return next();
            }

            let isOwner = false;

            // Check ownership based on resource type
            if (resourceType === 'user') {
                isOwner = userId === parseInt(resourceId);
            }

            if (!isOwner) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You do not own this resource.'
                });
            }

            next();

        } catch (error) {
            console.error('Ownership Check Error:', error);
            res.status(500).json({
                success: false,
                message: 'Error verifying ownership'
            });
        }
    };
};

/**
 * Audit logging helper
 */
async function logAuditEvent(userId, action, resourceType, resourceId, result, ipAddress, userAgent) {
    try {
        await db.query(`
            INSERT INTO audit_log 
            (user_id, action, resource_type, resource_id, action_result, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [userId, action, resourceType, resourceId, result, ipAddress, userAgent]);
    } catch (error) {
        console.error('Audit Log Error:', error);
    }
}

// ============================================
// ROLE-BASED AUTHORIZATION MIDDLEWARE
// ============================================
function authorizeRole(requiredRole) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== requiredRole) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        next();
    };
}


// ============================================
// EXPORT
// ============================================

module.exports = {
    ACLManager,
    requirePermission,
    requireRole,
    requireOwnership,
    logAuditEvent,
    authorizeRole,
    AccessControlMatrix,
    PolicyDocumentation
};