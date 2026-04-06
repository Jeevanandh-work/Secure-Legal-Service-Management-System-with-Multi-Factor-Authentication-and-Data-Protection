# Academic Project Report

## Title
Secure Legal Service Management System with Multi-Factor Authentication and Data Protection

## Certificate (Template)
This is to certify that the project titled "Secure Legal Service Management System with Multi-Factor Authentication and Data Protection" submitted by ____________________ (Roll No: ____________________) in partial fulfillment of the requirements for the award of the BTech degree in Computer Science and Engineering is a bonafide record of work carried out under my supervision.

- Guide Signature: ____________________
- Guide Name: ____________________
- Head of Department Signature: ____________________
- Date: ____________________

## Declaration (Template)
I hereby declare that this project report titled "Secure Legal Service Management System with Multi-Factor Authentication and Data Protection" is my original work and has not been submitted to any other institution or university for the award of any degree or diploma.

- Student Signature: ____________________
- Student Name: ____________________
- Roll Number: ____________________
- Date: ____________________

## Acknowledgement (Template)
I express my sincere gratitude to my project guide, department faculty, and institution for their valuable guidance and support during the development of this project. I also acknowledge the open-source communities and technical documentation resources that helped in implementing secure web development practices.

## Student and Submission Details
- Student Name: ____________________
- Roll Number: ____________________
- Department: Computer Science and Engineering
- Program: BTech
- Semester: ____________________
- Institution: ____________________
- Guide Name: ____________________
- Submission Date: ____________________

## Abstract
This project presents a secure full-stack legal service management platform developed using Flask and MongoDB Atlas. The system supports three user roles, Client, Lawyer, and Admin, and integrates practical cybersecurity controls for academic and real-world relevance. Core security mechanisms include bcrypt password hashing, OTP-based multi-factor authentication, AES-256 encryption for sensitive legal descriptions, role-based access control, input validation, secure sessions, and audit logging.

The design is mapped to major security principles through CIA triad coverage and threat-based mitigation strategies. The project demonstrates how secure software engineering practices can be embedded into a business workflow while maintaining usability and modularity.

## Keywords
- Cybersecurity
- Flask
- MongoDB Atlas
- Multi-Factor Authentication
- AES-256 Encryption
- RBAC
- Audit Logging
- Secure Web Application

## Table of Contents (Report Format)
1. Introduction
2. Problem Definition
3. Security Requirements
4. System Architecture
5. Modules Description
6. Security Mechanisms
7. Threat Analysis
8. Security Policies
9. CIA Triad Mapping
10. Innovation and Practical Application
11. Conclusion
12. Methodology
13. Implementation Outcomes
14. Future Enhancement Directions
15. References
16. Viva-Voce Quick Summary

## Objectives
- Build a secure legal service workflow for Client, Lawyer, and Admin roles.
- Protect user credentials using bcrypt password hashing.
- Enforce OTP-based second-factor authentication with expiry and attempt limits.
- Encrypt sensitive legal data using AES-256 before database storage.
- Enforce RBAC and object-level authorization checks.
- Maintain accountability through comprehensive security logging.
- Demonstrate academically relevant mapping between threats and controls.

## Scope and Limitations
- Scope:
    Implements web security controls in authentication, authorization, encryption, validation, and logging layers.
- Limitations:
    Conceptual firewall layer is documented but not physically configured in this codebase, and advanced production controls (WAF/SIEM/rate limiting) are suggested as future enhancements.

## 1. Introduction
Digital legal platforms handle highly sensitive case information and personally identifiable data. This project presents a secure web-based legal service system built with Flask and MongoDB Atlas, focusing on practical cybersecurity controls such as multi-factor authentication, encryption, role-based access control, and audit logging.

The goal is to provide a functional service workflow for Client, Lawyer, and Admin roles while preserving confidentiality, integrity, and availability of data.

## 2. Problem Definition
Traditional web applications in legal domains often face the following security challenges:
- Weak authentication and password-only access.
- Unauthorized cross-user data access.
- Sensitive legal descriptions stored in plaintext.
- Insufficient activity tracking for accountability.
- Exposure to injection and session-related attacks.

This project addresses these challenges by integrating layered security controls directly into the application workflow.

## 3. Security Requirements
The system security requirements are:
- Secure user registration and login.
- Multi-factor authentication using OTP.
- Password hashing using bcrypt.
- Encryption of sensitive legal case descriptions using AES-256.
- Strict Role-Based Access Control for Client, Lawyer, and Admin roles.
- Session security with timeout and protected cookie settings.
- Input validation and request-level authorization checks.
- Centralized logging and audit trail of security-critical actions.
- Secure cloud database communication with TLS.

## 4. System Architecture
### 4.1 Logical Architecture
User -> Flask Application -> Authentication & Authorization Layer -> Secure Business Routes -> MongoDB Atlas

### 4.2 Network Security Architecture (Conceptual Diagram)
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
Flask Web Server (Auth + Validation + RBAC + Logging)
    |\
    | \-- SMTP with TLS --> Gmail SMTP Server (OTP delivery)
    |
    \---- TLS-encrypted connection --> MongoDB Atlas
```

### 4.3 Architecture Notes
- HTTPS/SSL-TLS protects data in transit between client and server.
- MongoDB Atlas is accessed using TLS-enabled secure connection.
- OTP emails are sent through SMTP with TLS.
- Firewall is represented as a deployment layer to control inbound traffic (conceptual design requirement).

## 5. Modules Description
### 5.1 Authentication Module (utils/auth.py)
- Handles user registration and credential verification.
- Hashes passwords using bcrypt.
- Implements login-required and role-required decorators.
- Logs important security events.

### 5.2 OTP Module (utils/otp.py)
- Generates 6-digit OTP codes.
- Sends OTP via Gmail SMTP with TLS.
- Enforces OTP expiry (5 minutes) and maximum 3 attempts.

### 5.3 Encryption Module (utils/encryption.py)
- Encrypts sensitive legal case descriptions with AES-256-CBC.
- Uses random IV and PKCS7 padding.
- Decrypts encrypted case content for authorized viewers only.

### 5.4 Main Application (app.py)
- Defines secure routes for Client, Lawyer, and Admin workflows.
- Applies input validation and RBAC checks.
- Integrates session management and activity logging.

### 5.5 Data Layer (MongoDB Atlas)
- Stores users, lawyers, requests, responses, and logs collections.
- Uses TLS-secured cloud database connectivity.

## 6. Security Mechanisms
### 6.1 Password Security
- bcrypt hashing with configurable rounds.
- No plaintext password storage.

### 6.2 Multi-Factor Authentication
- OTP verification after password check.
- OTP validity: 5 minutes.
- Max attempts: 3.

### 6.3 Access Control
- RBAC roles: Client, Lawyer, Admin.
- Route-level and object-level access checks.

### 6.4 Data Encryption
- AES-256 encryption for case descriptions before persistence.
- Decryption only for authorized views.

### 6.5 Session Security
- Session timeout configured.
- Secure cookie policy with HttpOnly, SameSite, and Secure (production).

### 6.6 Logging and Auditing
- Records login success/failure, OTP verification, request access and updates.
- Supports accountability and forensic review.

### 6.7 Input Validation
- Validates required fields, email format, and payload constraints.
- Reduces injection and malformed input risk.

## 7. Threat Analysis
| Threat | Impact | Mitigation in System |
|--------|--------|----------------------|
| Data breach | Exposure of legal content | AES-256 encryption + TLS-secured database communication |
| Unauthorized access | Cross-user data access | RBAC decorators and request ownership/assignment checks |
| Brute-force attacks | Account compromise attempts | bcrypt slow hashing + logging + OTP second factor |
| Session hijacking | Unauthorized session reuse | Secure session cookies + timeout + server-side session controls |
| Injection attacks | Data manipulation/exfiltration | Input validation and controlled database query handling |
| OTP brute force | MFA bypass attempt | OTP expiry (5 min) + max 3 attempts |

## 8. Security Policies
### 8.1 Password Policy
- Minimum 8 characters.
- Recommended complexity: upper, lower, digit, special character.
- Hash-only storage using bcrypt.

### 8.2 OTP Policy
- 6-digit OTP.
- Expiration window: 5 minutes.
- Maximum verification attempts: 3.

### 8.3 Access Control Policy
- Roles: Client, Lawyer, Admin.
- Least-privilege access enforced by role and data ownership.
- Unauthorized requests are denied.

### 8.4 Data Privacy Policy
- No plaintext storage for sensitive legal descriptions.
- AES encryption for case descriptions.
- bcrypt hashing for passwords.

### 8.5 Backup and Recovery Policy
- Use MongoDB Atlas backup/snapshot capabilities.
- Maintain periodic backup schedule.
- Test restoration process in controlled environment.

## 9. CIA Triad Mapping
### 9.1 Confidentiality
Implemented using AES-256 encryption for legal case data and TLS-secured transport channels.

### 9.2 Integrity
Implemented through bcrypt-based credential verification, input validation, and controlled updates.

### 9.3 Availability
Supported by MongoDB Atlas managed cloud infrastructure, scalable access, and backup strategy.

## 10. Innovation and Practical Application
This project demonstrates practical real-world cybersecurity integration in an academic legal-service use case:
- OTP-based MFA adds robust identity assurance.
- AES encryption protects sensitive legal records.
- Audit logging provides traceability and compliance support.
- RBAC enforces business-aligned least-privilege access.
- MongoDB Atlas cloud usage aligns with modern scalable deployments.

## 11. Conclusion
The upgraded system satisfies key academic evaluation criteria by combining implementation and theoretical security foundations. It delivers a secure, role-aware legal service platform with encryption, MFA, validation, and auditing controls mapped clearly to practical threats and CIA principles.

The project can be further extended with deployment hardening (WAF integration, rate limiting, SIEM integration), but its current design already demonstrates a strong and complete cybersecurity-centered full-stack solution for BTech-level academic submission.

## 12. Methodology
The implementation followed a security-by-design approach:
- Requirement analysis based on legal-data confidentiality and role separation.
- Architecture design with layered security controls.
- Module implementation in Flask with dedicated utility modules for auth, OTP, and encryption.
- Security integration into route-level logic through validation, RBAC, and logging checks.
- Verification using functional and security-oriented test scenarios.
- Documentation-first refinement for academic evaluation readiness.

## 13. Implementation Outcomes
The final system demonstrates the following measurable outcomes:
- Secure authentication flow with password + OTP verification.
- Encrypted storage of sensitive case descriptions.
- Role-constrained access for all core workflows.
- Auditable activity trail for major security events.
- Cloud-ready data layer using MongoDB Atlas TLS connectivity.

## 14. Future Enhancement Directions
- Add rate limiting for login and OTP endpoints.
- Integrate centralized log analysis (SIEM).
- Deploy behind a managed WAF and reverse proxy.
- Introduce automated security tests in CI/CD pipeline.
- Add key-rotation procedure for encryption lifecycle management.

## 15. References
1. OWASP Foundation, OWASP Top 10 Web Application Security Risks.
2. NIST, Framework for Improving Critical Infrastructure Cybersecurity.
3. Flask Documentation, Pallets Projects.
4. MongoDB Atlas Security and TLS Documentation.
5. Python cryptography Library Documentation.
6. bcrypt Library Documentation for Python.

## 16. Viva-Voce Quick Summary
### 16.1 One-Minute Project Summary
This project is a secure legal-service web application built using Flask and MongoDB Atlas. It implements password hashing with bcrypt, OTP-based multi-factor authentication, AES-256 encryption for sensitive legal descriptions, role-based access control for Client/Lawyer/Admin, and audit logging for accountability. The design addresses major web threats such as unauthorized access, brute-force attempts, injection risks, and data exposure.

### 16.2 Key Security Controls to Explain in Viva
- bcrypt hashing for secure password storage.
- OTP policy: 6-digit OTP, 5-minute expiry, maximum 3 attempts.
- AES-256 encryption and controlled decryption for legal case details.
- RBAC and object-level authorization checks.
- Session security through timeout and secure cookie settings.
- Activity logging for forensic traceability.

### 16.3 Common Viva Questions and Short Answers
Q1. Why did you use bcrypt and not plain hashing like SHA-256 for passwords?
A: bcrypt is intentionally slow and salted, which makes brute-force and rainbow-table attacks significantly harder.

Q2. Why is OTP required after password login?
A: OTP adds a second factor, so stolen passwords alone cannot grant access.

Q3. What data is encrypted and why?
A: Sensitive legal case descriptions are encrypted using AES-256 to protect confidentiality in storage.

Q4. How is unauthorized data access prevented?
A: RBAC plus object-level checks ensure users only access data permitted for their role and ownership.

Q5. How does your system support CIA triad?
A: Confidentiality via AES/TLS, Integrity via validation and controlled updates, Availability via MongoDB Atlas managed cloud setup.

### 16.4 Final Outcome Statement
The project demonstrates both implementation depth and theoretical cybersecurity mapping, making it suitable for BTech academic evaluation and practical demonstration.

## 17. Screenshots Checklist (Mandatory for Final Report)
Include the following screenshots in the final PDF report:
- Screenshot 1: Login page with email/password form.
- Screenshot 2: OTP verification screen after login.
- Screenshot 3: Role-based dashboard (Client/Lawyer/Admin).
- Screenshot 4: Admin dashboard statistics cards (total users, total cases, pending requests).
- Screenshot 5: Admin logs page showing activity records.

Recommended screenshot notes:
- Add a 1-line caption below each screenshot.
- Mention what security feature is demonstrated (for example OTP, RBAC, logging).
