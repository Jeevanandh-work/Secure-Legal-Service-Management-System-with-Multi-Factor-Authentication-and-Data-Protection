# Secure Legal Service Management System with Multi-Factor Authentication and Data Protection

## Project Report

### Note
This report describes the current Flask-based implementation in the repository and is written in a format suitable for academic submission or project presentation.

---

## 1. Title Page

**Project Title:** Secure Legal Service Management System with Multi-Factor Authentication and Data Protection

**Domain:** Secure Web Application, Legal Service Workflow, Cybersecurity

**Technology Stack:** Flask, MongoDB Atlas, Jinja2, HTML/CSS, bcrypt, AES-256, SMTP OTP, Python

**Project Type:** Full-stack secure web application

**Roles Supported:** Client, Lawyer, Admin

---

## 2. Abstract

This project is a secure legal service management platform developed using Flask and MongoDB Atlas. It enables clients to submit legal service requests, lawyers to review and respond to assigned requests, and administrators to manage users, lawyers, requests, and system activity.

The system is designed with security as the central goal. It uses bcrypt for password hashing, OTP-based multi-factor authentication, AES-256 encryption for sensitive case descriptions, role-based access control, secure session handling, activity logging, and TLS-secured communication with MongoDB Atlas and SMTP.

The project demonstrates how modern security controls can be integrated into a practical workflow while keeping the application simple enough for academic evaluation and demonstration.

---

## 3. Introduction

Legal service platforms handle confidential personal and case information. A typical weakness in such systems is that they rely only on username-password login and store sensitive information in plain text. This project addresses those issues by introducing layered security controls and a role-based architecture.

The application supports three main user categories:

- Client: submits and tracks legal requests
- Lawyer: receives assigned requests and responds to them
- Admin: manages users, lawyers, requests, and logs

The frontend is designed as a professional law-firm style interface, while the backend focuses on secure data handling and controlled access.

---

## 4. Problem Statement

Many legal service systems face the following problems:

- weak authentication
- password-only access
- unauthorized access to case files
- plaintext storage of sensitive legal information
- lack of accountability and audit logs
- poor separation of duties between users
- no visible security governance

This project solves these problems by implementing authentication, encryption, authorization, validation, audit logging, and secure cloud database connectivity.

---

## 5. Objectives

The main objectives of the project are:

- provide secure login and registration
- enforce OTP-based multi-factor authentication
- protect passwords with bcrypt hashing
- encrypt sensitive legal case descriptions with AES-256
- restrict access using role-based access control
- log important user and admin actions
- provide a modern legal-service dashboard UI
- keep the system academically suitable and easy to present

---

## 6. Scope

### Included in the project

- user registration and login
- role-based dashboards
- legal request submission
- lawyer assignment and response handling
- admin user management
- activity logs
- password change functionality
- terms and privacy page
- secure frontend and responsive UI

### Not included as a built-in network layer

- dedicated hardware firewall inside the codebase
- WAF deployment
- SIEM integration
- cloud network security group configuration

These are deployment-level controls and can be added later.

---

## 7. Technology Stack

### Backend
- Python 3
- Flask
- PyMongo
- bcrypt
- cryptography
- SMTP utilities

### Frontend
- HTML5
- CSS3
- Jinja2 templates
- Font Awesome icons
- Google Fonts

### Database
- MongoDB Atlas

### Security Components
- OTP authentication
- AES-256 encryption
- secure session cookies
- RBAC decorators
- audit logging
- security headers

---

## 8. System Architecture

### 8.1 High-Level Architecture

User Browser -> Flask Application -> Authentication and Authorization Layer -> Business Routes -> MongoDB Atlas

### 8.2 Detailed Flow

1. User opens the website
2. User registers or logs in
3. Password is verified using bcrypt
4. OTP is sent to the registered email
5. OTP is verified before final session creation
6. User is redirected to a role-specific dashboard
7. Access to data is controlled based on role and ownership
8. Sensitive legal descriptions are encrypted before storage and decrypted only for authorized users
9. Important actions are written to audit logs

### 8.3 Conceptual Network Security View

- Browser communication should be protected with HTTPS in deployment
- Database communication uses MongoDB Atlas TLS
- OTP delivery uses Gmail SMTP with TLS
- A firewall layer is recommended in production deployment

---

## 9. Modules Description

### 9.1 `app.py`
This is the main Flask application file. It defines routes for:

- homepage
- login and logout
- OTP verification
- registration
- password change
- client dashboard
- lawyer dashboard
- admin dashboard
- request submission
- request viewing
- lawyer response
- admin user management
- admin request assignment
- admin logs
- error handling

It also initializes the MongoDB connection and the encryption and OTP managers.

### 9.2 `utils/auth.py`
This module handles:

- password hashing
- password verification
- user registration
- login authentication
- password change
- login-required decorator
- admin-required decorator
- lawyer-required decorator
- action logging

### 9.3 `utils/encryption.py`
This module provides:

- AES-256-CBC encryption
- random initialization vectors
- PKCS7 padding
- Base64 encoding for safe storage
- decryption for authorized access

### 9.4 `utils/otp.py`
This module provides:

- 6-digit OTP generation
- OTP expiry and verification
- email delivery through SMTP
- development fallback OTP support
- notification emails for login, request submission, and password change

### 9.5 `config.py`
This module stores application settings such as:

- secret key
- MongoDB URI
- encryption key
- mail configuration
- OTP settings
- password policy
- session configuration
- admin email whitelist

### 9.6 Templates
The `templates/` folder contains the Jinja2 pages for:

- base layout
- index page
- login
- register
- verify OTP
- client dashboard
- lawyer dashboard
- admin dashboard
- request submission
- request view
- respond request
- admin users
- admin add lawyer
- admin logs
- terms and privacy
- error pages
- change password

### 9.7 Static Files
The `static/style.css` file provides the responsive legal-style UI.

---

## 10. User Roles and Permissions

### 10.1 Client
Clients can:

- register and log in
- verify OTP
- submit legal requests
- view only their own requests
- see status updates and responses

Clients cannot:

- access other users' cases
- manage lawyers or users
- view system logs

### 10.2 Lawyer
Lawyers can:

- log in with OTP
- see only assigned requests
- decrypt and read case descriptions
- submit responses
- update case status

Lawyers cannot:

- view unassigned requests
- manage users
- access admin logs

### 10.3 Admin
Admins can:

- view the full dashboard
- manage users and roles
- activate or deactivate users
- add lawyers
- assign lawyers to cases
- view logs
- monitor activity

Admin access is restricted to a single authorized admin email through application-level whitelist enforcement.

---

## 11. Security Implementation

### 11.1 Password Hashing
Passwords are hashed using bcrypt with 12 rounds. This makes password cracking slower and prevents storing passwords in plain text.

### 11.2 OTP-Based Multi-Factor Authentication
After password verification, a 6-digit OTP is sent to the user’s email. The OTP expires in 5 minutes and allows a maximum of 3 attempts.

### 11.3 AES-256 Encryption
Sensitive legal descriptions are encrypted before storing them in the database. Decryption is performed only when an authorized user accesses the record.

### 11.4 Role-Based Access Control
Decorators and route checks ensure that users only access permitted pages and records.

### 11.5 Session Security
The application uses secure session settings:

- HttpOnly
- SameSite
- Secure in production
- automatic timeout

### 11.6 Logging and Auditing
The system logs actions such as:

- registration
- login success/failure
- OTP verification
- request submission
- request viewing
- request response
- user role updates
- user activation/deactivation
- password changes

### 11.7 Input Validation
Inputs are checked for required fields, length, and general correctness before being processed.

### 11.8 Security Headers
The application adds HTTP security headers to reduce browser-based attack risks.

---

## 12. Data Model Overview

### Collections in MongoDB

- `users`
- `lawyers`
- `requests`
- `responses`
- `logs`

### Important Stored Fields

#### users
- name
- email
- password hash
- role
- is_active
- failed_login_attempts
- lockout_until

#### requests
- user_id
- user_email
- case_type
- encrypted description
- assigned_lawyer_id
- status
- timestamps

#### responses
- request_id
- lawyer_id
- response_text
- timestamp

#### logs
- user
- action
- details
- timestamp
- IP address

---

## 13. Workflow Description

### 13.1 Registration Workflow
1. User opens register page
2. Form data is validated
3. Password is hashed with bcrypt
4. Client account is created
5. User can then log in

### 13.2 Login Workflow
1. User chooses role and enters email/password
2. Credentials are verified
3. Role match is checked
4. OTP is generated and sent by email
5. OTP is verified
6. Session is created
7. User is redirected to dashboard

### 13.3 Request Submission Workflow
1. Client opens request form
2. Case type and description are entered
3. Description is encrypted with AES-256
4. Request is saved in MongoDB
5. Action is logged
6. Notification email is sent

### 13.4 Lawyer Response Workflow
1. Lawyer opens assigned request
2. Encrypted description is decrypted for viewing
3. Lawyer writes response
4. Status is updated
5. Response is stored
6. Action is logged

### 13.5 Admin Management Workflow
1. Admin logs in through whitelisted email
2. Admin sees system statistics and logs
3. Admin updates roles or activates users
4. Admin assigns lawyers to cases
5. Admin monitors audit trail

---

## 14. Frontend Design

The frontend is designed like a professional legal services website.

### Visual Style
- dark blue and gold legal theme
- clean cards and spacing
- responsive layout
- professional typography
- modern icon set

### Main Pages
- home page with hero section
- login and register cards
- OTP verification page
- role dashboards
- admin tools pages

### User Experience Features
- professional navbar
- clear CTA buttons
- status badges
- tables with hover effects
- compact and readable forms
- dashboard role labels

---

## 15. Security Policies

### Password Policy
- minimum 8 characters
- bcrypt hashing
- no plaintext storage

### OTP Policy
- 6 digits
- 5-minute expiry
- 3 attempts maximum

### Access Control Policy
- client, lawyer, admin separation
- whitelisted admin access
- object-level authorization checks

### Data Privacy Policy
- no sensitive case data stored in plaintext
- encryption used for descriptions
- secure session cookies

### Backup and Recovery Policy
- Atlas backups should be enabled in production
- periodic snapshots should be maintained
- recovery testing should be performed regularly

---

## 16. Threat Analysis

| Threat | Risk | Mitigation |
|---|---|---|
| Password theft | Account compromise | bcrypt hashing + OTP |
| Brute force login | Unauthorized access | lockout policy + OTP |
| Data breach | Confidential legal data exposure | AES-256 encryption |
| Unauthorized access | Cross-user data exposure | RBAC + object checks |
| Session hijacking | Misuse of active session | secure cookies + timeout |
| Injection attacks | Data manipulation | input validation |
| Log tampering | Audit bypass | server-side logging |

---

## 17. CIA Triad Mapping

### Confidentiality
Protected using encryption, secure sessions, and role restrictions.

### Integrity
Protected using authenticated changes, controlled updates, and validation.

### Availability
Supported by cloud database hosting, modular design, and operational logging.

---

## 18. Testing and Verification

The system includes functional and security-focused validation such as:

- registration validation
- login and OTP verification
- role mismatch blocking
- client request ownership checks
- lawyer assignment checks
- admin-only pages
- audit log recording
- password change flow
- request encryption and decryption verification

The project has also been run locally and connected to MongoDB Atlas during development.

---

## 19. Deployment Notes

For deployment, the following should be configured:

- production secret key
- MongoDB Atlas IP allowlist
- valid SMTP credentials
- HTTPS reverse proxy
- firewall or cloud security group
- optional rate limiting and WAF

---

## 20. Limitations

- No dedicated firewall is implemented in code.
- Real email OTP depends on proper SMTP app-password configuration.
- MongoDB Atlas requires correct DNS and network allowlist configuration.
- Production deployment hardening should be added before public release.

---

## 21. Future Enhancements

- add firewall and WAF integration
- add rate limiting for login and OTP flows
- add file upload support for legal documents
- add chat or case messaging
- add PDF export for legal reports
- add two-person admin approval for role changes
- add SIEM integration for monitoring
- add analytics dashboard for case trends

---

## 22. Conclusion

This project demonstrates a complete secure legal service management workflow with modern authentication, encryption, access control, auditing, and a professional frontend. It is suitable for academic presentation because it combines practical implementation with security concepts such as confidentiality, integrity, availability, RBAC, MFA, and encrypted storage.

The application is also easy to extend for real-world deployment, especially by adding firewall controls, production monitoring, and stronger operational governance.

---

## 23. References

- Flask Documentation
- MongoDB Atlas Documentation
- bcrypt library documentation
- cryptography library documentation
- SMTP / TLS email security references
- OWASP Top 10

---

## 24. Viva-Voce Quick Summary

### What is this project?
A secure legal service management platform with MFA, encryption, RBAC, and logging.

### Why is it secure?
Because passwords are hashed, legal data is encrypted, access is restricted, and actions are logged.

### Which technologies are used?
Flask, MongoDB Atlas, bcrypt, AES-256, SMTP OTP, HTML/CSS, and Jinja2.

### What roles are supported?
Client, Lawyer, and Admin.

### What is the key innovation?
A legal workflow with real security controls embedded into every major action.

---

## 25. Appendix

### Suggested Student Details
- Name: ____________________
- Roll Number: ____________________
- Class/Semester: ____________________
- Department: ____________________
- Institution: ____________________
- Guide: ____________________
- Date: ____________________

### Suggested Screenshots for Report
- Home page
- Login page
- OTP page
- Client dashboard
- Lawyer dashboard
- Admin dashboard
- Request submission page
- Request detail page
- Response page
- Admin logs page

---

**End of Report**
