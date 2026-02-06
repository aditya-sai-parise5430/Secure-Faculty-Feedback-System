// ============================================
// CRYPTOGRAPHY UTILITIES
// File: backend/utils/cryptoUtils.js
// Purpose: All encryption, hashing, signing, encoding functions
// Components: Hashing(4.1), Encryption(3), Signatures(4.2), Encoding(5)
// ============================================

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const NodeRSA = require('node-rsa');
require('dotenv').config();

// ============================================
// COMPONENT 4.1: HASHING WITH SALT
// ============================================

class HashingService {
    /**
     * Hash password using bcrypt (automatic salt generation)
     * Bcrypt rounds: 12 (configurable via .env)
     */
    static async hashPassword(password) {
        const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
        const salt = await bcrypt.genSalt(saltRounds);
        const hash = await bcrypt.hash(password, salt);
        
        return { hash, salt };
    }

    /**
     * Verify password against stored hash
     */
    static async verifyPassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    /**
     * SHA-256 hashing for data integrity
     * Used for: content hashing, digital signatures
     */
    static hashData(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * HMAC for message authentication
     */
    static createHMAC(data, secret) {
        return crypto.createHmac('sha256', secret).update(data).digest('hex');
    }

    /**
     * Verify HMAC
     */
    static verifyHMAC(data, secret, expectedHmac) {
        const computedHmac = this.createHMAC(data, secret);
        return crypto.timingSafeEqual(
            Buffer.from(computedHmac),
            Buffer.from(expectedHmac)
        );
    }
}

// ============================================
// COMPONENT 3: ENCRYPTION & DECRYPTION
// Algorithm: AES-256-GCM (Authenticated Encryption)
// ============================================

class EncryptionService {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.masterKey = Buffer.from(process.env.ENCRYPTION_MASTER_KEY, 'hex');
        
        if (this.masterKey.length !== 32) {
            throw new Error('ENCRYPTION_MASTER_KEY must be 64 hex characters (32 bytes)');
        }
    }

    /**
     * Generate random encryption key (256-bit)
     */
    generateKey() {
        return crypto.randomBytes(32);
    }

    /**
     * Key Derivation Function using PBKDF2
     * Used for: deriving keys from passwords
     */
    deriveKey(password, salt, iterations = 100000) {
        return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
    }

    /**
     * COMPONENT 3.2: Encrypt data using AES-256-GCM
     * Returns: encrypted text, IV, and authentication tag
     */
    encrypt(plaintext) {
        // Generate random IV (Initialization Vector)
        const iv = crypto.randomBytes(16);
        
        // Create cipher
        const cipher = crypto.createCipheriv(this.algorithm, this.masterKey, iv);
        
        // Encrypt data
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        // Get authentication tag for integrity verification
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted: encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    /**
     * COMPONENT 3.2: Decrypt data using AES-256-GCM
     */
    decrypt(encrypted, iv, authTag) {
        try {
            // Create decipher
            const decipher = crypto.createDecipheriv(
                this.algorithm,
                this.masterKey,
                Buffer.from(iv, 'hex')
            );
            
            // Set authentication tag for verification
            decipher.setAuthTag(Buffer.from(authTag, 'hex'));
            
            // Decrypt data
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            throw new Error('Decryption failed: Data may be corrupted or tampered');
        }
    }

    /**
     * COMPONENT 3.1: Hybrid encryption with key exchange
     * Used for: demonstrating key exchange mechanism
     */
    encryptWithKeyExchange(plaintext, recipientPublicKey) {
        // Generate ephemeral symmetric key
        const symmetricKey = this.generateKey();
        
        // Encrypt plaintext with symmetric key
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
        
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        
        // Encrypt symmetric key with recipient's RSA public key
        const rsaKey = new NodeRSA(recipientPublicKey);
        const encryptedKey = rsaKey.encrypt(symmetricKey, 'base64');
        
        return {
            encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            encryptedKey  // This is the "key exchange"
        };
    }
}

// ============================================
// COMPONENT 4.2: DIGITAL SIGNATURES
// Algorithm: RSA-2048 with SHA-256
// ============================================

class DigitalSignatureService {
    constructor() {
        // Generate RSA key pair (2048-bit)
        this.keyPair = new NodeRSA({ b: 2048 });
        this.privateKey = this.keyPair.exportKey('private');
        this.publicKey = this.keyPair.exportKey('public');
    }

    /**
     * Create digital signature for data
     * Process: Hash data → Sign hash with private key
     */
    sign(data) {
        // Hash the data first
        const hash = crypto.createHash('sha256').update(data).digest();
        
        // Sign the hash with private key
        const signature = this.keyPair.sign(hash, 'base64');
        
        return signature;
    }

    /**
     * Verify digital signature
     * Returns: true if signature is valid, false otherwise
     */
    verify(data, signature) {
        const hash = crypto.createHash('sha256').update(data).digest();
        
        try {
            return this.keyPair.verify(hash, signature, 'buffer', 'base64');
        } catch (error) {
            return false;
        }
    }

    /**
     * Sign using pre-computed hash
     * Used for: efficiency when hash is already computed
     */
    signWithHash(dataHash) {
        return this.keyPair.sign(Buffer.from(dataHash, 'hex'), 'base64');
    }

    /**
     * Verify using pre-computed hash
     */
    verifyWithHash(dataHash, signature) {
        try {
            return this.keyPair.verify(
                Buffer.from(dataHash, 'hex'),
                signature,
                'buffer',
                'base64'
            );
        } catch (error) {
            return false;
        }
    }

    /**
     * Get public key (for sharing with others)
     */
    getPublicKey() {
        return this.publicKey;
    }

    /**
     * Get private key (keep secret!)
     */
    getPrivateKey() {
        return this.privateKey;
    }
}

// ============================================
// COMPONENT 5: ENCODING TECHNIQUES
// Techniques: Base64, URL-safe Base64
// ============================================

class EncodingService {
    /**
     * COMPONENT 5.1: Base64 encoding
     */
    static encodeBase64(data) {
        return Buffer.from(data, 'utf8').toString('base64');
    }

    /**
     * COMPONENT 5.1: Base64 decoding
     */
    static decodeBase64(encoded) {
        return Buffer.from(encoded, 'base64').toString('utf8');
    }

    /**
     * URL-safe Base64 encoding (for tokens, IDs)
     * Replaces: + with -, / with _, removes =
     */
    static encodeBase64URL(data) {
        return Buffer.from(data, 'utf8')
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * URL-safe Base64 decoding
     */
    static decodeBase64URL(encoded) {
        // Reverse URL-safe transformations
        let base64 = encoded
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        
        // Add padding
        while (base64.length % 4) {
            base64 += '=';
        }
        
        return Buffer.from(base64, 'base64').toString('utf8');
    }

    /**
     * Generate anonymous ID using encoding
     * Used for: anonymous feedback submission
     */
    static generateAnonymousId(userId, timestamp) {
        const data = `${userId}-${timestamp}-${crypto.randomBytes(8).toString('hex')}`;
        const hash = crypto.createHash('sha256').update(data).digest('hex');
        return this.encodeBase64URL(hash).substring(0, 16);
    }

    /**
     * Hex encoding (for display)
     */
    static encodeHex(data) {
        return Buffer.from(data, 'utf8').toString('hex');
    }

    /**
     * Hex decoding
     */
    static decodeHex(encoded) {
        return Buffer.from(encoded, 'hex').toString('utf8');
    }
}

// ============================================
// OTP SERVICE (for Multi-Factor Authentication)
// ============================================

class OTPService {
    /**
     * Generate random numeric OTP
     * Default: 6 digits
     */
    static generateOTP(length = 6) {
        const digits = '0123456789';
        let otp = '';
        
        for (let i = 0; i < length; i++) {
            const randomIndex = crypto.randomInt(0, digits.length);
            otp += digits[randomIndex];
        }
        
        return otp;
    }

    /**
     * Hash OTP before storing in database
     */
    static async hashOTP(otp) {
        const salt = await bcrypt.genSalt(10);
        return await bcrypt.hash(otp, salt);
    }

    /**
     * Verify OTP against stored hash
     */
    static async verifyOTP(otp, hash) {
        return await bcrypt.compare(otp, hash);
    }

    /**
     * Check if OTP has expired
     */
    static isExpired(expiryTimestamp) {
        return new Date() > new Date(expiryTimestamp);
    }

    /**
     * Calculate expiry time
     */
    static calculateExpiry(minutes = 10) {
        return new Date(Date.now() + minutes * 60 * 1000);
    }
}

// ============================================
// EXPORT ALL SERVICES
// ============================================

module.exports = {
    HashingService,
    EncryptionService,
    DigitalSignatureService,
    EncodingService,
    OTPService
};