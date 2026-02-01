# Secure Faculty Feedback System (SFFS)

A secure, anonymous, and role-based feedback system designed for educational institutions. This platform allows students to provide honest feedback to faculty members with a guarantee of anonymity through end-to-end encryption.

## Features

### Security & Privacy
- **Anonymous Feedback**: Student identities are decoupled from their feedback.
- **End-to-End Encryption**: Feedback content is encrypted using **AES-256-GCM** before storage.
- **Digital Signatures**: RSA-2048 signatures to ensure data integrity.
- **Multi-Factor Authentication (MFA)**: OTP-based login verification via Email.
- **Role-Based Access Control (RBAC)**: Strict separation between Students, Faculty, and Admins.
- **Audit Logging**: Tracks all critical system actions for security auditing.

### Advanced Features
- **QR Code Generation**: Faculty can generate QR codes containing their complete performance report (name, total reviews, average rating, and full decrypted feedback sorted by rating). Demonstrates advanced encoding techniques.
- **Password Visibility Toggle**: Eye icon on login and registration forms allows users to toggle password visibility for improved usability.

### User Roles
- **Student**: Submit anonymous feedback, rate faculty.
- **Faculty**: View received feedback, average ratings, and generate shareable QR performance reports.
- **Admin**: Manage the system, view aggregated performance data, moderate content.

## Tech Stack

- **Frontend**: Vanilla HTML5, CSS3, JavaScript (No framework required).
- **Backend**: Node.js, Express.js.
- **Database**: MySQL.
- **Security Libraries**:
  - `bcrypt`: Password hashing.
  - `jsonwebtoken`: Session management.
  - `crypto`: AES-256-GCM encryption.
  - `helmet`: HTTP security headers.
  - `express-rate-limit`: DDoS protection.
  - `qrcode`: QR code generation for encoding feedback reports.

## Prerequisites

- **Node.js** (v14 or higher)
- **MySQL Server**
- **Git**

## Installation & Setup

### 1. Database Setup
1. Open your MySQL client (Workbench, Command Line, etc.).
2. Run the schema script located in `database/schema.sql` to create the database and tables.
   ```sql
   source /path/to/database/schema.sql;
   ```
3. (Optional) Load sample data:
   ```sql
   source /path/to/database/sample-data.sql;
   ```

### 2. Backend Configuration
1. Navigate to the backend folder:
   ```bash
   cd backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Configure the environment variables:
   - The `.env` file is pre-configured for local development.
   - **Important**: Ensure `DB_PASSWORD` in `.env` matches your local MySQL password.
   - Default Port: `5001`.

### 3. Run the Server
Start the backend server:
```bash
node server.js
# OR for development with auto-restart
npm run dev
```
You should see: `Server running on port 5001`.

### 4. Frontend Access
1. Navigate to the `frontend` folder.
2. Open `index.html` in any modern web browser.
   - **Note**: Since the API is running on localhost, you can simply open the file directly (file://) or serve it with a lightweight server like Live Server.

## Security Architecture

### Feedback Encryption Flow
1. **Submission**: User submits feedback.
2. **Encryption**: Server generates a unique initialization vector (IV) and encrypts text using AES-256-GCM with a master key.
3. **Storage**: The encrypted text, IV, and auth tag are stored in the `feedback` table.
4. **Retrieval**: When a faculty member views feedback, the server decrypts it on-the-fly.

### Authentication Flow
1. User logs in with Username/Password.
2. If credentials match, an OTP is generated and sent to the registered email.
3. User enters OTP.
4. Server issues a JWT (JSON Web Token) for the session.

## Project Structure

```
secure-feedback-system/
├── backend/            # Express.js Server
│   ├── config/         # Database connection
│   ├── controllers/    # Business logic
│   ├── middleware/     # Auth, Rate limiting
│   ├── routes/         # API endpoints
│   ├── utils/          # Encryption & Email helpers
│   ├── .env            # Environment Configuration
│   └── server.js       # Entry point
├── database/           # SQL Scripts
│   ├── schema.sql      # Table structure
│   └── sample-data.sql # Mock data
├── frontend/           # Client-side
│   └── index.html      # Single Page Application (SPA)
└── docs/               # Documentation
```

## License
Proprietary - For Educational Use Only.
