# 🧪 Testing & Sample Data Guide

Complete testing guide with sample data and test scenarios for the Secure Legal Service Management System.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Sample Data](#sample-data)
3. [Testing Scenarios](#testing-scenarios)
4. [Security Testing](#security-testing)
5. [Performance Testing](#performance-testing)

---

## Getting Started

### Prerequisites

1. Complete installation (see README.md)
2. MongoDB Atlas running
3. Gmail account configured for SMTP
4. Flask app started on localhost:5000

### Browser Setup

```
Recommended browsers for testing:
- Chrome (for developer tools)
- Firefox (for inspector)
- Edge (for testing)

Open Chrome DevTools:
- Right-click → Inspect
- Network tab to see requests
- Application tab to see cookies/storage
- Console tab to test JavaScript
```

---

## Sample Data

### Admin Account

```
Email:    admin@legal.com
Password: AdminSecure123!@
Role:     admin

# Create with:
flask create-admin
# Or manually:
python -c "
from app import auth_manager
result = auth_manager.register_user(
    'Admin User',
    'admin@legal.com',
    'AdminSecure123!@',
    'admin'
)
print(result)
"
```

### Sample Client Accounts

```
Client 1:
Email:    client1@example.com
Password: ClientPass123!@
Role:     client

Client 2:
Email:    client2@example.com
Password: ClientPass456!@
Role:     client
```

### Sample Lawyer Accounts

```
Lawyer 1:
Email:    lawyer1@example.com
Password: LawyerPass123!@
Specialization: criminal
Role:     lawyer

Lawyer 2:
Email:    lawyer2@example.com
Password: LawyerPass456!@
Specialization: corporate
Role:     lawyer
```

### Sample Legal Requests

```
Request 1: Criminal Case
- Client: client1@example.com
- Case Type: Criminal
- Description: "I was involved in a vehicle accident and was cited for reckless driving. 
                The accident causes minor property damage but no injuries. 
                I believe the citation is unjustified."

Request 2: Corporate Matter
- Client: client2@example.com
- Case Type: Corporate
- Description: "My business partner is threatening to dissolve our partnership agreement. 
                We have a binding contract signed in 2020. 
                Need advice on legal options and potential damages."

Request 3: Family Law
- Client: client1@example.com
- Case Type: Family
- Description: "Seeking custody modification for my two children. 
                Current arrangement no longer works due to job relocation. 
                Previous settlement was agreed upon in 2019."
```

---

## Testing Scenarios

### Scenario 1: User Registration & Login

**Goal:** Test authentication flow with password hashing and OTP

**Steps:**

1. Open http://localhost:5000/register
2. Fill form:
   ```
   Name: Test User
   Email: testuser@example.com
   Password: TestPass123!@
   Confirm Password: TestPass123!@
   ```
3. Click "Create Account"
4. **Expected:** Success message "Registration successful"
5. Go to http://localhost:5000/login
6. Enter credentials:
   ```
   Email: testuser@example.com
   Password: TestPass123!@
   ```
7. **Expected:** Redirected to OTP page with message about email sent
8. Check email for 6-digit OTP (in development, check Flask logs)
9. Enter OTP (you need to check Flask console/logs for the generated OTP)
10. **Expected:** Logged in, redirected to dashboard

**Verification:**
- Check terminal logs: "OTP sent to testuser@example.com"
- Verify password NOT stored with `mongosh`:
  ```javascript
  use legal_service
  db.users.findOne({email: 'testuser@example.com'})
  // password field should be bcrypt hash like: $2b$12$...
  ```

---

### Scenario 2: Test Password Hashing

**Goal:** Verify bcrypt hashing is working

**Steps:**

```python
# In Python shell:
from utils.auth import AuthManager
from app import db

auth = AuthManager(db, hash_rounds=12)

# Hash a password
password = "TestPassword123!@"
hashed = auth.hash_password(password)
print(f"Original: {password}")
print(f"Hashed:   {hashed}")

# Verify it's different each time (different salt)
hashed2 = auth.hash_password(password)
print(f"Hashed2:  {hashed2}")
print(f"Same?     {hashed == hashed2}")  # Should be False

# Verify password matching
print(f"Match?    {auth.verify_password(password, hashed)}")  # Should be True
print(f"Wrong?    {auth.verify_password('wrong', hashed)}")    # Should be False
```

**Expected Output:**
```
Original: TestPassword123!@
Hashed:   $2b$12$abcdef...  (40+ character bcrypt hash)
Hashed2:  $2b$12$xyz...     (different from first)
Same?     False
Match?    True
Wrong?    False
```

---

### Scenario 3: Test AES-256 Encryption

**Goal:** Verify encryption/decryption of case descriptions

**Steps:**

```python
# In Python shell:
from utils.encryption import EncryptionManager
from config import DevelopmentConfig

enc = EncryptionManager(DevelopmentConfig.ENCRYPTION_KEY)

# Encrypt a case description
original = "Client is facing charges for grand larceny. Case scheduled for trial."
encrypted = enc.encrypt(original)
print(f"Original:  {original}")
print(f"Encrypted: {encrypted[:50]}...  ({len(encrypted)} chars)")

# Decrypt
decrypted = enc.decrypt(encrypted)
print(f"Decrypted: {decrypted}")
print(f"Match?     {original == decrypted}")

# Encrypt same plaintext again (should be different due to random IV)
encrypted2 = enc.encrypt(original)
print(f"Same encrypted? {encrypted == encrypted2}")  # Should be False
print(f"But both decrypt to same? {enc.decrypt(encrypted2) == original}")  # True
```

**Expected Output:**
```
Original:  Client is facing charges...
Encrypted: aVZPSDJFNU4zK1VN... (80-100+ chars, no spaces)
Decrypted: Client is facing charges...
Match?     True
Same encrypted? False
But both decrypt to same? True
```

---

### Scenario 4: Test OTP Expiration

**Goal:** Verify OTP expires after 5 minutes

**Steps:**

1. Start fresh login: http://localhost:5000/login
2. Get OTP sent (check logs)
3. **Wait 5+ minutes** (or modify test to speed up)
4. Try entering the OTP
5. **Expected:** Error message "OTP expired. Valid for only 5 minutes."

**To Test Quickly:**

```python
# Modify config.py temporarily:
OTP_EXPIRY_MINUTES = 0  # Immediate expiry

# Then test login flow
# Or modify otp.py line to bypass wait:
# In verify_otp(), change timedelta(minutes=...) to timedelta(seconds=5)
```

---

### Scenario 5: Test OTP Attempt Limit

**Goal:** Verify max 3 OTP verification attempts

**Steps:**

1. Generate OTP (via login)
2. Go to OTP verification page
3. Enter wrong OTP
4. **Expected:** Error "Invalid OTP. 2 attempts remaining."
5. Enter wrong OTP again
6. **Expected:** Error "Invalid OTP. 1 attempts remaining."
7. Enter wrong OTP third time
8. **Expected:** Error "Maximum 3 OTP attempts exceeded. Request new OTP."
9. Try correct OTP
10. **Expected:** Fails (already exceeded attempts)

---

### Scenario 6: Client Submits Encrypted Request

**Goal:** Test case description encryption before storage

**Steps:**

1. Login as client (client1@example.com)
2. Click "Submit New Legal Request"
3. Fill form:
   ```
   Case Type: Criminal
   Description: "I was arrested for shoplifting..."
   ```
4. Click "Submit Request"
5. **Expected:** Success message, redirected to dashboard
6. Verify in MongoDB:
   ```javascript
   db.requests.findOne({user_id: ObjectId('...')})
   // description_encrypted should be base64, not plaintext
   // description field should NOT exist
   ```

**Verification in MongoDB:**
```javascript
// Check encrypted data
db.requests.findOne({case_type: 'Criminal'})

// Output looks like:
{
  _id: ObjectId(...),
  user_id: ObjectId(...),
  case_type: 'Criminal',
  description_encrypted: 'aVZPSDJFNU4zK1VDbHRodlI2hUn...',  // Encrypted
  status: 'pending',
  created_at: ISODate(...)
}

// Try to decode (will fail without key):
// It's base64 but the plaintext is encrypted inside
```

---

### Scenario 7: Lawyer Views & Decrypts Case

**Goal:** Test on-demand decryption when lawyer views case

**Steps:**

1. Login as lawyer (lawyer1@example.com)
2. Dashboard shows assigned cases
3. Click "View" on a request
4. **Verify:** Case description is displayed in plaintext
5. This only works for this lawyer
6. Check logs show "REQUEST_VIEWED" action

**Technical Flow:**
```python
# When lawyer views request:
request_doc = db.requests.find_one({'_id': request_id})

# Decrypt on-demand
decrypted = encryption_manager.decrypt(request_doc['description_encrypted'])

# Show decrypted to lawyer
# Database still stores encrypted data
# Another user can't decrypt (no key visible to client)
```

---

### Scenario 8: Test Authorization/Access Control

**Goal:** Verify RBAC prevents unauthorized access

**Steps:**

1. **Test Client → Lawyer Request:**
   - Login as client1@example.com
   - Get request_id from dashboard
   - Try to navigate to lawyer response page
   - **Expected:** 403 Forbidden error

2. **Test Lawyer → Wrong Case:**
   - Login as lawyer2@example.com
   - Get request_id for case assigned to lawyer1@example.com
   - Try to directly access: `/respond-request/{request_id}`
   - **Expected:** 403 Forbidden error

3. **Test Non-Admin → Admin Panel:**
   - Login as client1@example.com
   - Try to access: `/admin/users`
   - **Expected:** Redirect to login or 403 error

---

### Scenario 9: Testing Session Timeout

**Goal:** Verify 30-minute session timeout

**Steps:**

1. Login successfully
2. Modify time (for testing):
   ```python
   # In config.py, change timeout to 1 minute:
   PERMANENT_SESSION_LIFETIME = timedelta(minutes=1)
   ```
3. Stay idle for >1 minute
4. Make any request (click a link)
5. **Expected:** Redirect to login page, "Session expired" message

---

### Scenario 10: Test Activity Logging

**Goal:** Verify all actions are logged

**Steps:**

1. Perform various actions:
   - Register new account
   - Login (success)
   - Try login with wrong password (failure)
   - Submit request
   - View request
   - Logout

2. Check logs in MongoDB:
   ```javascript
   db.logs.find({}).sort({timestamp: -1}).limit(10)
   ```

3. **Expected:** See entries like:
   ```
   USER_REGISTERED
   LOGIN_SUCCESS
   LOGIN_FAILED
   REQUEST_SUBMITTED
   REQUEST_VIEWED
   LOGOUT (as recorded in code)
   ```

---

## Security Testing

### Test 1: Verify Password Not Retrievable

**Goal:** Ensure passwords are one-way hashed

```python
from app import db

user = db['users'].find_one({'email': 'testuser@example.com'})
password_hash = user['password']

# Try to reverse hash (impossible)
# bcrypt hashes are one-way
# Even with the source code, can't extract password

# Can only verify with:
import bcrypt
password_guess = "TestPass123!@"
is_correct = bcrypt.checkpw(password_guess.encode(), password_hash.encode())
```

### Test 2: Verify Encrypted Case Can't Be Read in DB

**Goal:** Ensure case descriptions aren't readable from database

```javascript
// In MongoDB:
db.requests.findOne({case_type: 'Criminal'})

// Output shows encrypted blob:
{
  description_encrypted: "aVZPSDJFNU4zK1VNZ2lXRDJQU1Q4NWpHRXgvL0F..."
}

// Try to decode with standard base64 decoders
// Still encrypted! Encryption is password-independent
// Only app with ENCRYPTION_KEY can decrypt
```

### Test 3: Verify Session Cookie Security

**Goal:** Check that session cookies can't be accessed by JavaScript

```javascript
// In browser console (DevTools), try:
console.log(document.cookie)

// Output: Should be EMPTY or minimal
// Session cookie has HttpOnly flag
// JavaScript CANNOT read it
// Prevents XSS attacks from stealing session
```

### Test 4: OTP Timing Attack

**Goal:** Verify OTP verification uses constant-time comparison

```python
import time
from utils.otp import OTPManager

otp_mgr = OTPManager({...})

# Verify OTP (should take same time regardless of position of error)
# This is handled by Python's default comparison
# For true constant-time, would use hmac.compare_digest:

import hmac
hmac.compare_digest('123456', '123457')  # Always same time
```

### Test 5: SQL/NoSQL Injection

**Goal:** Verify inputs can't be used for injection attacks

```python
# Try malicious email:
malicious_email = {"$ne": None}  # NoSQL injection attempt

from app import db
# This will fail because we validate input types:
user = db['users'].find_one({'email': malicious_email})
# Error: validate_input returns False for non-string

# Frontend sends JSON {'$ne': None}, not string
# We validate: if not isinstance(email, str): reject
```

---

## Performance Testing

### Test 1: Bcrypt Timing

**Goal:** Verify bcrypt is appropriately slow (not too fast)

```python
import time
from utils.auth import AuthManager
from app import db

auth = AuthManager(db, hash_rounds=12)

# Measure hash time
start = time.time()
hash1 = auth.hash_password("TestPassword123!@")
hash_time = time.time() - start

print(f"Hash time: {hash_time:.3f} seconds")
# Expected: 0.2-0.5 seconds (intentionally slow)

# Measure verify time
start = time.time()
is_valid = auth.verify_password("TestPassword123!@", hash1)
verify_time = time.time() - start

print(f"Verify time: {verify_time:.3f} seconds")
# Expected: 0.2-0.5 seconds (same as hash time)
```

### Test 2: Encryption Performance

**Goal:** Verify AES-256 encryption is fast

```python
import time
from utils.encryption import EncryptionManager
from config import DevelopmentConfig

enc = EncryptionManager(DevelopmentConfig.ENCRYPTION_KEY)

large_text = "Sample case description. " * 1000  # ~25KB

start = time.time()
encrypted = enc.encrypt(large_text)
encrypt_time = time.time() - start

start = time.time()
decrypted = enc.decrypt(encrypted)
decrypt_time = time.time() - start

print(f"Encrypt 25KB: {encrypt_time*1000:.2f}ms")
print(f"Decrypt 25KB: {decrypt_time*1000:.2f}ms")
# Expected: <10ms each (fast)
```

### Test 3: Database Query Performance

**Goal:** Verify indexes are working

```python
import time
from app import db

# Find by email (indexed)
start = time.time()
for _ in range(100):
    db['users'].find_one({'email': 'test@example.com'})
indexed_time = time.time() - start

# Find by unindexed field
start = time.time()
for _ in range(100):
    db['users'].find_one({'is_active': True})
unindexed_time = time.time() - start

print(f"Indexed query: {indexed_time*1000:.2f}ms for 100 queries")
print(f"Unindexed query: {unindexed_time*1000:.2f}ms for 100 queries")
# Indexed should be significantly faster
```

---

## Test Checklist

### Authentication
- [ ] User can register (password hashed with bcrypt)
- [ ] User receives OTP via email
- [ ] OTP expires after 5 minutes
- [ ] OTP max 3 attempts enforced
- [ ] Successful login creates session
- [ ] Logout clears session
- [ ] Session timeout after 30 minutes

### Authorization
- [ ] Client can't access admin panel
- [ ] Lawyer can't view unassigned cases
- [ ] Admin can access everything
- [ ] 403 Forbidden returned for unauthorized access

### Encryption
- [ ] Case descriptions encrypted before storage
- [ ] Encrypted data unreadable in database
- [ ] Lawyer can decrypt when viewing case
- [ ] Encryption uses AES-256-CBC

### Data Security
- [ ] Passwords not stored in plaintext
- [ ] Sensitive fields not logged
- [ ] No secrets in source code
- [ ] HTTPS enforced (in production)

### Logging & Auditing
- [ ] Login attempts logged
- [ ] Request submissions logged
- [ ] Access to cases logged
- [ ] Admin actions logged
- [ ] Logs available for review

---

## Continuous Testing

### Automated Tests (Recommended)

```python
# Create tests.py
import unittest
from app import app

class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
    
    def test_registration(self):
        response = self.app.post('/register', data={
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'TestPass123!@',
            'confirm_password': 'TestPass123!@'
        })
        self.assertEqual(response.status_code, 302)  # Redirect

# Run with:
# python -m pytest tests.py -v
```

---

**Last Updated:** April 2024  
**Version:** 1.0.0
