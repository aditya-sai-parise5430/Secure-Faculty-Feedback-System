# Lab Evaluation Implementation Report
**Course:** 23CSE313 - Foundations of Cyber Security
**Project:** Secure Faculty Feedback System

This document maps your project's code to the specific requirements listed in the Lab Evaluation 1 rubrics. Use this to demonstrate your implementation during the Viva.

---

## 1. Authentication (3 Marks)

###  Single-Factor Authentication (1.5m)
**Requirement:** Implementation using password/PIN/username-based login.
**Implementation:**
-   **Main Need:** To verify the identity of users (students/faculty) before allowing access to the system.
-   **Algorithm Used:** `bcrypt` (Blowfish-based hashing).
-   **Justification:** `bcrypt` is computationally expensive and slow by design, making it highly resistant to brute-force and rainbow table attacks compared to fast hashes like MD5 or SHA-256.
-   **File:** `backend/utils/cryptoUtils.js` (Class: `HashingService`)

###  Multi-Factor Authentication (1.5m)
**Requirement:** Implementation using at least two factors (e.g., password + OTP).
**Implementation:**
-   **Main Need:** To add a second layer of defense; if a password is stolen, the attacker still cannot access the account without the second factor.
-   **Algorithm Used:** `TOTP` (Time-based One-Time Password) concept over Email.
-   **Justification:** Email-based OTP is a widely accessible and standard MFA method that balances security with user convenience without requiring specialized hardware tokens.
-   **File:** `backend/utils/cryptoUtils.js` (Class: `OTPService`)

---

## 2. Authorization - Access Control (3 Marks)

###  Access Control Model
**Requirement:** ACL with minimum 3 subjects and 3 objects.
**Implementation:**
-   **Main Need:** To ensure users can only perform actions relevant to their role (e.g., Students shouldn't read other faculty's feedback).
-   **Algorithm Used:** `RBAC` (Role-Based Access Control) with an Access Control Matrix.
-   **Justification:** RBAC scales better than Discretionary Access Control (DAC) for organizational structures like universities, where permissions are tied to roles (Student, Admin) rather than individuals.
-   **File:** `backend/middleware/accessControl.js`

###  Policy Definition & Justification (1.5m)
**Requirement:** Clearly define and justify access rights.
**Implementation:**
-   **Main Need:** To formally document who can do what and why, preventing "privilege creep".
-   **Approach:** Explicit `PolicyDocumentation` object mapping roles to justification strings.
-   **Justification:** Hardcoding policies ensures they are immutable and auditable, adhering to the "Principle of Least Privilege".

###  Implementation of Access Control (1.5m)
**Requirement:** Enforce permissions programmatically.
**Implementation:**
-   **Main Need:** To intercept every request and validate permissions before executing business logic.
-   **Algorithm Used:** Middleware Interception Chain.
-   **Justification:** Using Express middleware decouples security logic from business logic, ensuring a consistent security posture across all endpoints.

---

## 3. Encryption (3 Marks)

###  Key Exchange Mechanism (1.5m)
**Requirement:** Demonstrate secure key generation or key exchange method.
**Implementation:**
-   **Main Need:** To safely share a symmetric key over an insecure channel.
-   **Algorithm Used:** `RSA-OAEP` (Hybrid Encryption).
-   **Justification:** Asymmetric encryption (RSA) is slow but secure for key exchange, while symmetric encryption (AES) is fast for data. Combining them (Hybrid) gives the best of both worlds.
-   **File:** `backend/utils/cryptoUtils.js` (`encryptWithKeyExchange`)

###  Encryption & Decryption (1.5m)
**Requirement:** Implement secure encryption (AES, RSA, hybrid).
**Implementation:**
-   **Main Need:** To protect sensitive feedback data at rest so that even database admins cannot read it.
-   **Algorithm Used:** `AES-256-GCM` (Advanced Encryption Standard in Galois/Counter Mode).
-   **Justification:** GCM provides both confidentiality (encryption) and integrity (authentication), preventing attackers from tampering with encrypted data without detection.
-   **File:** `backend/utils/cryptoUtils.js` (Class: `EncryptionService`)

---

## 4. Hashing & Digital Signature (3 Marks)

###  Hashing with Salt (1.5m)
**Requirement:** Secure storage using hashing along with salt.
**Implementation:**
-   **Main Need:** To store passwords irreversibly so they cannot be recovered even if the database is leaked.
-   **Algorithm Used:** `bcrypt` (Auto-salting).
-   **Justification:** Salting ensures that two users with the same password have different hashes, defeating pre-computed rainbow table attacks.

###  Digital Signature using Hash (1.5m)
**Requirement:** Demonstrate data integrity and authenticity.
**Implementation:**
-   **Main Need:** To prove that a document (feedback report) originated from a trusted source and hasn't been altered.
-   **Algorithm Used:** `RSA-SHA256` (RSA signing of a SHA-256 hash).
-   **Justification:** SHA-256 creates a unique fingerprint of the data, and RSA signing ensures only the holder of the private key could have created that fingerprint.
-   **File:** `backend/utils/cryptoUtils.js` (Class: `DigitalSignatureService`)

---

## 5. Encoding Techniques (3 Marks)

###  Encoding & Decoding Implementation (1m)
**Requirement:** Base64 / QR Code / Barcode.
**Implementation:**
-   **Main Need:** To represent binary data (images, encrypted text) in a format suitable for text-based transport or physical scanning.
-   **Algorithm Used:** `QR Code` (Quick Response Code) and `Base64`.
-   **Justification:** QR codes are the industry standard for physical-to-digital bridging due to their high error correction and data density. Base64 is essential for sending binary encryption output over JSON/HTTP.
-   **File:** `backend/controllers/feedbackController.js` (QR Generation)

###  Theory Components (2m)
*Be prepared to answer these verbally:*
-   **Security Levels & Risks:** Encoding (Base64) is **NOT** encryption. It only changes representation, providing **zero confidentiality**.
-   **Possible Attacks:** Decoding attacks (trivial), URL injection (prevented by Base64URL).

---

## Conclusion
**Status:**  **100% Compliant**
Your codebase contains code blocks explicitly matching every requirement in the Lab Evaluation rubric.
