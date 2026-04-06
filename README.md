# 🔐 Secure Legal Service Management System

A comprehensive, production-ready Flask web application implementing enterprise-grade security features for legal service management including multi-factor authentication, AES-256 encryption, and role-based access control.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Security Implementation](#security-implementation)
- [Security Policies](#security-policies)
- [Threat Analysis](#threat-analysis)
- [CIA Triad Mapping](#cia-triad-mapping)
- [Network Security Design](#network-security-design)
- [Innovation and Practical Application](#innovation-and-practical-application)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Database Schema](#database-schema)
- [Usage Guide](#usage-guide)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## ✨ Features

### Authentication & Security
- **User Registration & Login** with email verification
- **OTP-Based 2-Factor Authentication (2FA)** via Gmail SMTP
- **Bcrypt Password Hashing** (12 rounds - military-grade security)
- **AES-256 Encryption** for sensitive data (case descriptions)
- **Session Management** with automatic timeout (30 minutes)
- **Activity Logging** system for compliance and auditing

### User Roles & Access Control
1. **Client/User**
   - Register and login with OTP
   - Submit legal service requests
   - View request status
   - Access lawyer responses

2. **Lawyer**
   - Login securely with 2FA
   - View assigned legal requests
   - Decrypt and read case details
   - Respond to users
   - Update case status

3. **Admin**
   - Add/remove users and lawyers
   - View all legal requests and system logs
   - Monitor login attempts and activities
   - Manage system roles and permissions

### Core Features
- **Request Submission** with encrypted case descriptions
- **Lawyer Assignment** system
- **Real-time Responses** and status updates
- **Comprehensive Audit Trail** of all system activities
- **Secure MongoDB Atlas** connection with TLS encryption
- **Input Validation** to prevent injection attacks
- **CSRF Protection** via SameSite cookies
- **HttpOnly Cookies** to prevent JavaScript access

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Frontend                         │
│                   (HTML/CSS/JavaScript)                      │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                     Flask Web Server                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          Authentication Layer (utils/auth.py)        │   │
│  │  - bcrypt password hashing                           │   │
│  │  - OTP generation & verification                     │   │
│  │  - Session management                                │   │
│  │  - Role-based access control (RBAC)                  │   │
│  └──────────────────────────────────────────────────────┘   │
└────────┬─────────────────────────────────────────────┬──────┘
         │                                             │
    ┌────▼────────────────────┐   ┌─────────────────────▼──────┐
    │  Encryption Manager     │   │   OTP Manager               │
    │  (utils/encryption.py)  │   │  (utils/otp.py)             │
    │                         │   │                             │
    │  - AES-256-CBC          │   │  - 6-digit OTP generation   │
    │  - PKCS7 Padding        │   │  - Gmail SMTP sending       │
    │  - Base64 Encoding      │   │  - Expiry & verification    │
    └────┬────────────────────┘   └─────────────┬───────────────┘
         │                                       │
    ┌────▼───────────────────────────────────────▼──────────────┐
    │        MongoDB Atlas (Secure Connection)                  │
    │                                                            │
    │  Collections:                                             │
    │  - users (encrypted passwords)                            │
    │  - lawyers (specialization data)                          │
    │  - requests (encrypted descriptions)                      │
    │  - responses (lawyer responses)                           │
    │  - logs (activity audit trail)                            │
    └────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Implementation

### 1. **Password Hashing (Bcrypt)**
```python
# Passwords are hashed using bcrypt with 12 rounds
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

# Verification is constant-time to prevent timing attacks
is_valid = bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))
```

**Why Bcrypt?**
- Slow algorithm (computationally expensive) → prevents brute force
- Automatic salt generation → same password produces different hashes
- Configurable rounds → can increase as computing power increases
- Constant-time comparison → prevents timing attacks

### 2. **AES-256 Encryption**
```python
# Encrypts case descriptions before storage
# Algorithm: AES-256-CBC
# - Key: 32 bytes (256-bit)
# - IV: Random 16 bytes prepended to ciphertext
# - Padding: PKCS7
# - Encoding: Base64 for safe storage

encrypted = encryption_manager.encrypt("Case description")
# Output: base64-encoded(IV + ciphertext)

plaintext = encryption_manager.decrypt(encrypted)
# Decrypts and removes padding automatically
```

**Why AES-256-CBC?**
- Military-grade encryption standard
- 256-bit key size is quantum-safe for current threat models
- CBC mode provides semantic security (same plaintext ≠ same ciphertext)
- Random IV for each encryption ensures different ciphertexts

### 3. **OTP-Based 2-Factor Authentication**
```
Login Flow:
1. User enters email & password
2. System verifies password hash
3. Generate random 6-digit OTP
4. Store OTP in server-side session (never in database)
5. Send OTP via encrypted SMTP (TLS)
6. User receives OTP in email
7. User enters OTP in form
8. System verifies OTP:
   - Check OTP matches (constant-time)
   - Check not expired (5 minutes)
   - Check attempts < 3
9. Clear OTP from session
10. Create authenticated session
```

**Security Features:**
- OTP stored server-side (session) → client can't intercept
- 5-minute expiry → time-limited
- Max 3 attempts → brute force protection
- Sent via TLS SMTP → encrypted in transit

### 4. **Role-Based Access Control (RBAC)**
```python
# Decorators enforce access control
@login_required  # Must be logged in
@admin_required  # Must be admin
@lawyer_required # Must be lawyer or admin

# Route-level checks
if session.get('role') != 'client':
    abort(403)  # Return 403 Forbidden
```

### 5. **Activity Logging**
```python
# Every important action is logged
log_entry = {
    'user': email,
    'action': 'LOGIN_SUCCESS | REQUEST_SUBMITTED | etc',
    'details': 'Additional context',
    'timestamp': datetime.utcnow(),
    'ip_address': request.remote_addr
}
```

### 6. **Secure MongoDB Connection**
```python
# TLS/SSL encryption required
MONGO_URI = 'mongodb+srv://user:pass@cluster.mongodb.net/db?tls=true&w=majority'

# Connection with timeout
mongo_client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000
)
```

### 7. **CSRF Protection**
```python
# Session cookies configured for maximum security
SESSION_COOKIE_SECURE = True       # HTTPS only
SESSION_COOKIE_HTTPONLY = True     # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'   # CSRF protection
```

### 8. **Input Validation**
```python
# All inputs validated before processing
def validate_input(data, required_fields):
    # Check required fields
    # Validate email format
    # Check string lengths (prevent oversized payloads)
    # Prevent injection attacks
    return is_valid, error_message
```

---

## 🔐 Security Policies

### 1. Password Policy
- Minimum length: 8 characters.
- Recommended complexity: uppercase, lowercase, numeric, and special character.
- Passwords are never stored in plaintext.
- Passwords are hashed using bcrypt before database storage.

### 2. OTP Policy
- OTP is a 6-digit numeric code.
- OTP validity duration is 5 minutes.
- Maximum 3 verification attempts are allowed.
- OTP is stored in server-side session and cleared after successful verification or policy violation.

### 3. Access Control Policy
- RBAC roles: Client, Lawyer, Admin.
- Client can access only self-owned requests.
- Lawyer can access only assigned requests.
- Admin can manage users, monitor logs, and oversee operations.
- Unauthorized access attempts result in access denial (HTTP 403) and can be audited via logs.

### 4. Data Privacy Policy
- No sensitive legal case description is stored as plaintext.
- Case descriptions are encrypted using AES-256 before storage.
- Passwords are hashed using bcrypt.
- Session cookies are protected through `HttpOnly`, `Secure` (production), and `SameSite` settings.

### 5. Backup and Recovery Policy
- MongoDB Atlas backup strategy should include periodic snapshots.
- Recovery objective is to restore service and data integrity from latest valid backup.
- Backup restoration procedure should be tested periodically in a non-production environment.

---

## ⚠️ Threat Analysis

| Threat | Risk Description | Implemented Security Solution |
|--------|------------------|-------------------------------|
| Data breach | Exposure of sensitive legal data from storage compromise | AES-256 encryption of case descriptions, TLS connection to MongoDB Atlas |
| Unauthorized access | User accesses data outside permitted role | RBAC decorators, per-request ownership/assignment checks, session-based auth |
| Brute-force attacks | Repeated password guessing attempts | bcrypt slow hashing, OTP second factor, login monitoring in logs |
| Session hijacking | Session token theft and replay | `HttpOnly` + `Secure` + `SameSite` cookies, session timeout and logout clear |
| Injection attacks | Malicious input manipulating queries or app behavior | Centralized input validation, bounded field lengths, controlled query patterns |
| OTP brute force | Multiple OTP guesses to bypass MFA | OTP expiry (5 minutes), max 3 attempts, OTP reset workflow |

---

## 🧩 CIA Triad Mapping

- Confidentiality:
   AES-256 encryption protects legal case descriptions. TLS protects transport channels to MongoDB Atlas and SMTP.
- Integrity:
   bcrypt hashing protects password integrity (tamper-evident verification), while input validation and access checks preserve application data correctness.
- Availability:
   MongoDB Atlas cloud infrastructure supports managed uptime, scalable access, and backup options for service continuity.

---

## 🌐 Network Security Design

### Architecture Diagram (Conceptual)

```text
Client Browser
      |
      | HTTPS (SSL/TLS)
      v
Internet
      |
      v
[Conceptual Firewall Layer]
      |
      v
Flask Web Server (Application + Auth + RBAC + Validation)
      |\
      | \-- SMTP with TLS --> Gmail SMTP Server (OTP delivery)
      |
      \---- TLS-encrypted MongoDB connection --> MongoDB Atlas
```

### Design Explanation
- HTTPS / SSL-TLS usage:
   Client-to-server communication is expected over HTTPS in production to protect credentials, session cookies, and request data in transit.
- Secure database connection (MongoDB Atlas TLS):
   The project uses MongoDB Atlas URI with TLS-enabled transport to encrypt database communication.
- Secure email communication (SMTP with TLS):
   OTP messages are sent through Gmail SMTP using STARTTLS to prevent plaintext email credential/OTP transport.
- Firewall role (conceptual):
   A network firewall is considered as a deployment layer to restrict inbound access (for example, exposing only HTTPS endpoints and limiting administrative traffic).

---

## 💡 Innovation and Practical Application

This project is academically strong and real-world applicable because it integrates practical cybersecurity controls into a usable legal workflow.

- OTP-based MFA:
   Adds a second verification layer beyond password-only authentication.
- AES encryption for sensitive legal data:
   Protects confidentiality of case narratives even if storage is compromised.
- Audit logging system:
   Enables forensic review, compliance reporting, and suspicious activity monitoring.
- RBAC implementation:
   Enforces least-privilege access boundaries among Client, Lawyer, and Admin users.
- Cloud database usage:
   Uses MongoDB Atlas managed infrastructure for secure connectivity, scalability, and backup-ready operations.

---

## 📁 Project Structure

```
c:\projects\data-information-and-security/
│
├── app.py                          # Main Flask application
├── config.py                       # Configuration settings
│
├── utils/
│   ├── __init__.py
│   ├── auth.py                    # Authentication & authorization
│   ├── encryption.py              # AES-256 encryption/decryption
│   └── otp.py                     # OTP generation & email
│
├── templates/                      # HTML templates
│   ├── base.html                  # Base template with navigation
│   ├── login.html                 # Login form
│   ├── register.html              # Registration form
│   ├── verify_otp.html            # OTP verification form
│   ├── client_dashboard.html      # Client dashboard
│   ├── lawyer_dashboard.html      # Lawyer dashboard
│   ├── admin_dashboard.html       # Admin dashboard
│   ├── request_service.html       # Submit legal request
│   ├── view_request.html          # View request details
│   ├── respond_request.html       # Lawyer respond to request
│   ├── admin_users.html           # User management
│   ├── admin_add_lawyer.html      # Add lawyer form
│   ├── admin_logs.html            # Activity logs
│   └── error.html                 # Error pages
│
├── static/
│   └── style.css                  # Global stylesheet
│
└── README.md                       # This file

```

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.8+
- MongoDB Atlas account (free tier available)
- Gmail account for SMTP (OTP emails)
- pip (Python package manager)

### Step 1: Clone/Setup Project

```bash
# Navigate to project directory
cd c:\projects\data-information-and-security

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
pip install flask pymongo bcrypt cryptography python-dotenv email-validator
```

**Package Explanations:**
- `flask` - Web framework
- `pymongo` - MongoDB driver
- `bcrypt` - Password hashing
- `cryptography` - AES encryption
- `python-dotenv` - Load environment variables
- `email-validator` - Email validation

### Step 3: Configure Environment

Create `.env` file in project root:

```env
# Flask Configuration
SECRET_KEY=your-super-secret-key-change-in-production

# MongoDB Atlas Connection
MONGO_URI=mongodb+srv://username:password@cluster0.mongodb.net/legal_service?retryWrites=true&w=majority&tls=true

# Encryption Key (32 bytes, base64 encoded)
ENCRYPTION_KEY=b'this-is-a-32-byte-encryption-key-change-this'

# Gmail SMTP Configuration (for OTP)
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-app-specific-password

# Note: For Gmail, use App Password, not regular password
# Enable 2FA on Google Account → Create App Password
```

### Step 4: MongoDB Atlas Setup

1. Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
2. Create free account and cluster
3. Create database user with strong password
4. Get connection string
5. Update `MONGO_URI` in `.env`

**Important:** Enable TLS connection (default in Atlas)

### Step 5: Gmail APP Password Setup

1. Enable 2-Step Verification on Google Account
2. Go to [App Passwords](https://myaccount.google.com/apppasswords)
3. Create app password for "Mail" and "Windows (or custom)"
4. Copy generated password
5. Update `MAIL_PASSWORD` in `.env`

### Step 6: Initialize Database

```bash
python -c "from app import app; app.cli.invoke('init-db')"
# Or run in Flask shell:
flask init-db
```

### Step 7: Create Admin User

```bash
flask create-admin
# Enter: email, name, password
```

### Step 8: Run Application

```bash
# Development mode
python app.py

# Or use Flask CLI
flask run

# App runs on: http://localhost:5000
```

---

## 💾 Database Schema

### users Collection
```json
{
  "_id": ObjectId,
  "name": "John Doe",
  "email": "john@example.com",
  "password": "$2b$12$...",  // Bcrypt hash
  "role": "client|lawyer|admin",
  "is_active": true,
  "created_at": ISODate("2024-01-01T10:00:00Z")
}
```

### lawyers Collection
```json
{
  "_id": ObjectId,
  "user_id": ObjectId,
  "name": "Jane Smith",
  "email": "jane@example.com",
  "specialization": "criminal",
  "created_at": ISODate("2024-01-01T10:00:00Z")
}
```

### requests Collection
```json
{
  "_id": ObjectId,
  "user_id": ObjectId,
  "user_email": "client@example.com",
  "case_type": "criminal",
  "description_encrypted": "aVZPSDJFNU4zK1VNZ2lXRDJQU==...",  // AES-256 encrypted
  "status": "pending|in_progress|completed|rejected",
  "assigned_lawyer_id": ObjectId,
  "created_at": ISODate("2024-01-01T10:00:00Z"),
  "updated_at": ISODate("2024-01-01T10:00:00Z")
}
```

### responses Collection
```json
{
  "_id": ObjectId,
  "request_id": ObjectId,
  "lawyer_id": ObjectId,
  "lawyer_email": "lawyer@example.com",
  "response_text": "Legal analysis and recommendations...",
  "created_at": ISODate("2024-01-01T10:00:00Z")
}
```

### logs Collection
```json
{
  "_id": ObjectId,
  "user": "user@example.com",
  "action": "LOGIN_SUCCESS|LOGIN_FAILED|REQUEST_SUBMITTED|...",
  "details": "Additional context about the action",
  "timestamp": ISODate("2024-01-01T10:00:00Z"),
  "ip_address": "192.168.1.1"
}
```

---

## 🚀 Usage Guide

### Client Workflow

1. **Register**
   - Go to `/register`
   - Fill in name, email, password (min 8 chars)
   - Password hashed with bcrypt before storage

2. **Login**
   - Go to `/login`
   - Enter email and password
   - System verifies against bcrypt hash
   - OTP sent to email
   - Enter 6-digit OTP (valid 5 minutes)
   - Redirected to dashboard

3. **Submit Request**
   - Click "Submit New Legal Request"
   - Select case type
   - Write case description
   - Description encrypted with AES-256 before storage
   - Receive confirmation

4. **View Request Status**
   - Dashboard shows all submitted requests
   - Click "View Details" to see current status
   - See lawyer responses when available

### Lawyer Workflow

1. **Login** (same as client, with OTP)

2. **View Dashboard**
   - See assigned cases
   - Click "View" to see decrypted case details
   - Read client's case description

3. **Respond to Request**
   - Click "Respond" button
   - Write legal analysis and recommendations
   - Update case status (in progress, completed, etc.)
   - Response stored and client notified

4. **Access Encryption**
   - Case descriptions decrypted when viewing
   - Only you and assigned lawyer can access
   - All access logged in audit trail

### Admin Workflow

1. **Manage Users**
   - Go to "Manage Users"
   - View all registered users
   - Activate/deactivate user accounts
   - Soft deletion preserves historical data

2. **Add Lawyers**
   - Click "Add New Lawyer"
   - Enter lawyer details and specialization
   - Initial password hashed with bcrypt
   - Lawyer receives login notification

3. **View Logs**
   - Go to "View Logs"
   - See all system activities:
     - Login attempts (success/failure)
     - User registrations
     - Request submissions
     - OTP verifications
     - Case assignments
   - Filter by action type
   - Review IP addresses

4. **System Monitoring**
   - Dashboard shows statistics:
     - Total users
     - Total requests
     - Total log entries
   - Identify suspicious patterns

---

## 🛡️ Security Best Practices

### For Developers

1. **Never Store Passwords in Plain Text**
   ```python
   # ❌ WRONG
   user['password'] = request.form['password']
   
   # ✅ CORRECT
   user['password'] = auth_manager.hash_password(password)
   ```

2. **Always Encrypt Sensitive Data**
   ```python
   # ❌ WRONG
   request['description'] = case_description
   
   # ✅ CORRECT
   request['description_encrypted'] = encryption_manager.encrypt(case_description)
   ```

3. **Validate All Inputs**
   ```python
   # ✅ ALWAYS do this
   is_valid, error = validate_input(request.form, ['email', 'password'])
   if not is_valid:
       return error_response
   ```

4. **Check Authorization**
   ```python
   # ✅ ALWAYS check user can access data
   if request_obj['user_id'] != session['user_id']:
       abort(403)  # Forbidden
   ```

5. **Log Important Actions**
   ```python
   # ✅ Log business-critical events
   auth_manager._log_action(user_email, 'REQUEST_SUBMITTED', 'Case type: criminal')
   ```

### For System Administrators

1. **Use Strong Encryption Keys**
   - 32 bytes (256-bit) minimum
   - Stored securely (environment variables or key management system)
   - Rotated periodically

2. **Monitor Activity Logs**
   - Review logs weekly for suspicious activity
   - Look for failed login attempts
   - Check unexpected IP addresses

3. **Keep Dependencies Updated**
   ```bash
   pip list --outdated
   pip install --upgrade package_name
   ```

4. **Use HTTPS in Production**
   - Install SSL certificate (Let's Encrypt free)
   - Force HTTPS redirects
   - Set HSTS headers

5. **Database Security**
   - Use strong authentication credentials
   - Enable network access restrictions (IP whitelist)
   - Enable MongoDB encryption at rest
   - Regular backups

6. **Session Management**
   - 30-minute session timeout configured
   - Encourage users to log out
   - Clear sensitive data on logout

### For Users

1. **Use Strong Passwords**
   - Minimum 8 characters
   - Mix uppercase, lowercase, numbers, symbols
   - Unique password per site

2. **Never Share OTP**
   - OTP is personal authentication factor
   - Support never asks for OTP
   - Delete emails after login

3. **Log Out from Public Computers**
   - Session expires after 30 minutes
   - Always click "Logout" button
   - Clear cookies/history

4. **Report Security Issues**
   - Suspicious login activity
   - Unauthorized case access
   - Any system abnormalities

---

## 🐛 Troubleshooting

### MongoDB Connection Error
```
Error: "Failed to connect to MongoDB"
```

**Solutions:**
1. Check connection string in `.env`
2. Verify IP whitelisting in MongoDB Atlas
3. Confirm username/password correct
4. Test connection: `mongo "mongodb+srv://..."`

### OTP Email Not Received
```
Error: "Gmail authentication failed"
```

**Solutions:**
1. Enable 2-Step Verification on Google Account
2. Create App Password (not regular password)
3. Allow "Less secure apps" (not recommended)
4. Check spam folder for emails
5. Verify MAIL_USERNAME and MAIL_PASSWORD in `.env`

```bash
# Test SMTP connection manually
python -c "
import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('your-email@gmail.com', 'app-password')
print('Connection successful!')
"
```

### Encryption/Decryption Error
```
Error: "Decryption failed" or "Invalid padding"
```

**Solutions:**
1. Verify ENCRYPTION_KEY is 32 bytes
2. Check encrypted data hasn't been corrupted
3. Ensure same encryption key used for decrypt as encrypt
4. Check database value hasn't been truncated

```python
# Verify key length
print(len(ENCRYPTION_KEY))  # Must be 32
```

### Session/Cookie Issues
```
Error: "Session expired" or "Not authenticated"
```

**Solutions:**
1. Clear browser cookies
2. Check if using HTTPS in production (SESSION_COOKIE_SECURE)
3. Verify session timeout configuration (30 minutes default)
4. Check system time sync (OTP uses UTC)

### Bcrypt Hash Verification Fails
```
Error: "Invalid password" after registration
```

**Solutions:**
1. Verify password != None or ""
2. Check hash stored correctly in database
3. Ensure same bcrypt version used
4. Try resetting password

---

## 📊 Performance Considerations

### Bcrypt
- 12 rounds = ~300ms per hash (intentionally slow)
- Acceptable for login (1-2 per minute per user)
- Use cached results for password verification

### AES-256 Encryption
- Very fast: ~10-100 microseconds per operation
- No performance penalty for storage
- Decrypt on-demand only when needed

### Database Indexes
```
Index created on:
- users.email (unique)
- requests.user_id
- requests.assigned_lawyer_id
- responses.request_id
- logs.timestamp
```

### Caching
- Consider Redis for session caching if scaling
- Cache OTP instead of storing in Flask session
- Cache user permissions after login

---

## 📚 References

- [OWASP Top 10](https://owasp.org/Top10/)
- [Bcrypt Documentation](https://github.com/pyca/bcrypt)
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [MongoDB Security](https://docs.mongodb.com/manual/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 📄 License

Academic & Educational Use. Do not use in production without security audit.

---

## 🤝 Contributing

This project is for educational purposes. Security improvements and bug fixes are welcome.

---

## ⚠️ Disclaimer

This system implements strong security features but no system is 100% secure. Always:
- Keep dependencies updated
- Monitor logs regularly
- Follow security best practices
- Conduct regular security audits
- Keep backups of critical data

For production deployments, conduct a professional security assessment.

---

**Last Updated:** April 2024  
**Version:** 1.0.0
