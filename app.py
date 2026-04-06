"""
Secure Legal Service Management System
Main Flask Application with authentication, encryption, and RBAC

Security Features Implemented:
1. OTP-based 2-factor authentication
2. Bcrypt password hashing
3. AES-256 encryption for sensitive data
4. Role-based access control (RBAC)
5. Activity logging system
6. Secure MongoDB Atlas connection (TLS)
7. Session-based authentication with timeouts
8. Input validation and sanitization
9. CSRF protection via SameSite cookies
10. HttpOnly cookies to prevent JavaScript access

Architecture:
User → Flask App → Authentication Layer → Secure API → MongoDB Atlas
"""

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from pymongo import MongoClient
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import custom modules
from config import Config, DevelopmentConfig
from utils.encryption import EncryptionManager
from utils.otp import OTPManager
from utils.auth import AuthManager, login_required, admin_required, lawyer_required, validate_input

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(DevelopmentConfig)


@app.after_request
def set_security_headers(response):
    """HTTP security headers to reduce XSS/clickjacking/content-sniffing risks."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Initialize encryption manager
encryption_manager = EncryptionManager(app.config['ENCRYPTION_KEY'])

# MongoDB Connection with TLS (Secure)
try:
    mongo_client = MongoClient(
        app.config['MONGO_URI'],
        serverSelectionTimeoutMS=5000,  # Connection timeout
        connectTimeoutMS=10000
    )
    # Verify connection
    mongo_client.admin.command('ping')
    db = mongo_client['legal_service']
    print("✓ MongoDB Atlas connected successfully with TLS encryption")
except Exception as e:
    print(f"✗ MongoDB connection failed: {str(e)}")
    print("  Using local MongoDB fallback (not recommended for production)")
    mongo_client = MongoClient('mongodb://localhost:27017/')
    db = mongo_client['legal_service']

# Initialize authentication and OTP managers
auth_manager = AuthManager(
    db,
    hash_rounds=app.config['HASH_ROUNDS'],
    max_failed_attempts=app.config['LOGIN_MAX_FAILED_ATTEMPTS'],
    lockout_minutes=app.config['LOGIN_LOCKOUT_MINUTES']
)
otp_manager = OTPManager({
    'MAIL_SERVER': app.config['MAIL_SERVER'],
    'MAIL_PORT': app.config['MAIL_PORT'],
    'MAIL_USE_TLS': app.config['MAIL_USE_TLS'],
    'MAIL_USERNAME': app.config['MAIL_USERNAME'],
    'MAIL_PASSWORD': app.config['MAIL_PASSWORD'],
    'OTP_LENGTH': app.config['OTP_LENGTH'],
    'OTP_EXPIRY_MINUTES': app.config['OTP_EXPIRY_MINUTES'],
    'OTP_MAX_ATTEMPTS': app.config['OTP_MAX_ATTEMPTS']
})


# ============================================================================
# SECURITY DECORATOR: Prevent accessing pages when logged in
# ============================================================================
def not_logged_in(f):
    """Redirect logged-in users away from login/register pages"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# HOME AND AUTHENTICATION ROUTES
# ============================================================================

@app.route('/')
def index():
    """Home page - redirects to dashboard if logged in, else to login"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
@not_logged_in
def register():
    """
    User registration with secure password hashing
    
    Security Features:
    - Input validation to prevent injection
    - Password minimum 8 characters
    - Bcrypt hashing (12 rounds)
    - Log registration attempt
    """
    if request.method == 'POST':
        data = request.form
        
        # Validate input
        is_valid, error_msg = validate_input(data, ['name', 'email', 'password', 'confirm_password'])
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('register'))
        
        # Check passwords match
        if data['password'] != data['confirm_password']:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        # Check password strength
        if len(data['password']) < app.config['PASSWORD_MIN_LENGTH']:
            flash(f"Password must be at least {app.config['PASSWORD_MIN_LENGTH']} characters", 'error')
            return redirect(url_for('register'))
        
        # Register user
        result = auth_manager.register_user(
            name=data['name'],
            email=data['email'],
            password=data['password'],
            role='client'  # Default role
        )
        
        if result['success']:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash(result['message'], 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@not_logged_in
def login():
    """
    User login with email and password
    Triggers OTP sending for 2FA
    
    Security Features:
    - Input validation
    - Check credentials against bcrypt hash
    - Log login attempts (success/failure)
    - Initiate OTP flow for 2FA
    """
    if request.method == 'POST':
        data = request.form
        
        # SECURITY VALIDATION: sanitize and validate user-supplied login fields.
        is_valid, error_msg = validate_input(data, ['email', 'password', 'role'])
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('login'))

        selected_role = data.get('role', '').strip().lower()
        allowed_roles = {'client', 'lawyer', 'admin'}
        if selected_role not in allowed_roles:
            flash('Please select a valid role.', 'error')
            return redirect(url_for('login'))
        
        allowed_admin_email = app.config.get('ADMIN_ALLOWED_EMAIL', 'admin@example.com')

        # Enforce a single admin login identity.
        if selected_role == 'admin' and data['email'].strip().lower() != allowed_admin_email:
            flash('Only the authorized admin email can login as Admin.', 'error')
            return redirect(url_for('login'))

        # AUTHENTICATION: verify password against bcrypt hash in database.
        result = auth_manager.authenticate_user(data['email'], data['password'])
        
        if result['success']:
            user = result['user']

            # Enforce role-based login selection before OTP is generated.
            if user['role'] != selected_role:
                flash(f'Role mismatch: this account is registered as {user["role"].capitalize()}.', 'error')
                return redirect(url_for('login'))

            # Defense-in-depth: even if DB role is admin, block non-whitelisted admin email.
            if user['role'] == 'admin' and user['email'].strip().lower() != allowed_admin_email:
                flash('This admin account is not authorized for admin access.', 'error')
                return redirect(url_for('login'))
            
            # Store user info temporarily (before OTP verification)
            session['temp_user_id'] = user['id']
            session['temp_user_email'] = user['email']
            session['temp_user_name'] = user['name']
            session['temp_user_role'] = user['role']
            
            # MFA AUTHENTICATION: send OTP as second factor before final session login.
            otp_result = otp_manager.send_otp(user['email'], user['name'])
            
            if otp_result['success']:
                flash(f'OTP sent to {user["email"]}. Enter it to complete login.', 'info')
                return redirect(url_for('verify_otp'))
            else:
                flash(otp_result['message'], 'error')
                session.clear()
                return redirect(url_for('login'))
        else:
            flash(result['message'], 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
@not_logged_in
def verify_otp():
    """
    OTP verification for 2-Factor Authentication
    
    Security Features:
    - OTP expires in 5 minutes
    - Maximum 3 attempts
    - OTP stored server-side (session), not visible to client
    - Clear sensitive data after verification
    """
    # Check if user is in login process
    if 'temp_user_email' not in session:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        
        # Validate OTP input
        if not otp or len(otp) != 6 or not otp.isdigit():
            flash('Invalid OTP format. Please enter 6 digits.', 'error')
            return redirect(url_for('verify_otp'))
        
        # Verify OTP
        result = otp_manager.verify_otp(otp)
        
        if result['valid']:
            # OTP verified - create session
            session['user_id'] = session.pop('temp_user_id')
            session['email'] = session.pop('temp_user_email')
            session['name'] = session.pop('temp_user_name')
            session['role'] = session.pop('temp_user_role')
            session.permanent = True
            app.permanent_session_lifetime = \
                app.config['PERMANENT_SESSION_LIFETIME']
            
            # Log successful 2FA
            auth_manager._log_action(
                session['email'],
                'OTP_VERIFIED',
                '2-Factor authentication completed'
            )

            # Notification email for login success (product-like behavior).
            otp_manager.send_notification(
                session['email'],
                'Login Successful - Legal Service Platform',
                f"Hello {session['name']},\n\nYour account login was successful on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC.\nIf this was not you, change your password immediately.\n\nRegards,\nSecurity Team"
            )
            
            flash(f'Welcome back, {session["name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(result['message'], 'error')
            return redirect(url_for('verify_otp'))
    
    email = session.get('temp_user_email', '')
    debug_otp = session.get('otp_debug')
    return render_template('verify_otp.html', email=email, debug_otp=debug_otp)


@app.route('/logout')
def logout():
    """Secure logout - clear all session data"""
    if 'email' in session:
        auth_manager._log_action(session['email'], 'LOGOUT', 'User logged out')
    
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/terms-privacy')
def terms_privacy():
    """Public terms and privacy page for policy transparency."""
    return render_template('terms_privacy.html')


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow logged-in users to change password securely."""
    from bson import ObjectId

    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return redirect(url_for('change_password'))

        result = auth_manager.change_password(ObjectId(session['user_id']), current_password, new_password)
        if result['success']:
            otp_manager.send_notification(
                session['email'],
                'Password Changed - Legal Service Platform',
                f"Hello {session.get('name', 'User')},\n\nYour password was changed on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC.\nIf you did not perform this action, contact support immediately.\n\nRegards,\nSecurity Team"
            )
            flash('Password changed successfully.', 'success')
            return redirect(url_for('dashboard'))

        flash(result['message'], 'error')
        return redirect(url_for('change_password'))

    return render_template('change_password.html')


# ============================================================================
# CLIENT ROUTES - Submit and view legal requests
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main dashboard - shows role-specific content
    
    RBAC: Each role sees different content
    - Client: Their requests
    - Lawyer: Assigned requests to respond to
    - Admin: System overview
    """
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    if user_role == 'client':
        # Show client's requests
        requests_collection = db['requests']
        user_requests = list(requests_collection.find({'user_id': user_id}))
        
        # Convert ObjectId to string for templates
        for req in user_requests:
            req['_id'] = str(req['_id'])
        
        return render_template('client_dashboard.html', 
                             user_name=session.get('name'),
                             requests=user_requests)
    
    elif user_role == 'lawyer':
        # Show requests assigned to lawyer
        requests_collection = db['requests']
        query = {'assigned_lawyer_id': user_id}

        # Optional lawyer filter for case type and status.
        case_type_filter = request.args.get('case_type', '').strip()
        status_filter = request.args.get('status', '').strip()
        if case_type_filter:
            query['case_type'] = case_type_filter
        if status_filter:
            query['status'] = status_filter

        assigned_requests = list(requests_collection.find(query))
        
        for req in assigned_requests:
            req['_id'] = str(req['_id'])
        
        return render_template('lawyer_dashboard.html',
                             user_name=session.get('name'),
                             requests=assigned_requests,
                             selected_case_type=case_type_filter,
                             selected_status=status_filter)
    
    elif user_role == 'admin':
        # Show admin overview
        users_count = db['users'].count_documents({})
        requests_count = db['requests'].count_documents({})
        logs_count = db['logs'].count_documents({})
        pending_requests_count = db['requests'].count_documents({'status': 'pending'})
        
        recent_logs = list(db['logs'].find().sort('timestamp', -1).limit(10))
        
        return render_template('admin_dashboard.html',
                             user_name=session.get('name'),
                             users_count=users_count,
                             requests_count=requests_count,
                             logs_count=logs_count,
                             pending_requests_count=pending_requests_count,
                             recent_logs=recent_logs)


@app.route('/request-service', methods=['GET', 'POST'])
@login_required
def request_service():
    """
    Submit new legal service request
    
    Security Features:
    - Input validation
    - Case description encrypted before storage (AES-256)
    - User ID automatically added (cannot be spoofed)
    - Activity logged
    
    Encryption Process:
    1. Get plaintext description from form
    2. Encrypt using AES-256-CBC
    3. Store encrypted blob in MongoDB
    4. Only lawyer with decryption key can read
    """
    # RBAC ENFORCEMENT: only client role is permitted to submit legal requests.
    if session.get('role') != 'client':
        flash('Only clients can submit requests', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        data = request.form
        
        # SECURITY VALIDATION: check required fields and constrain request payload.
        is_valid, error_msg = validate_input(data, ['case_type', 'description'])
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('request_service'))
        
        try:
            # ENCRYPTION POINT: sensitive case description is AES-encrypted before storage.
            encrypted_description = encryption_manager.encrypt(data['description'])
            
            # Create request document
            request_doc = {
                'user_id': session.get('user_id'),
                'user_email': session.get('email'),
                'case_type': data['case_type'],
                'description_encrypted': encrypted_description,  # ENCRYPTED!
                'status': 'pending',
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow()
            }
            
            # Insert into database
            result = db['requests'].insert_one(request_doc)
            
            # Log action
            auth_manager._log_action(
                session['email'],
                'REQUEST_SUBMITTED',
                f'Legal request submitted: {data["case_type"]}'
            )

            otp_manager.send_notification(
                session['email'],
                'New Legal Request Submitted',
                f"Hello {session.get('name', 'User')},\n\nYour legal request ({data['case_type']}) was submitted on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC.\n\nRegards,\nLegal Service Platform"
            )
            
            flash('Legal request submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            flash(f'Error submitting request: {str(e)}', 'error')
            return redirect(url_for('request_service'))
    
    return render_template('request_service.html')


@app.route('/request/<request_id>')
@login_required
def view_request(request_id):
    """
    View specific request details
    
    Security Features:
    - Only client who submitted or assigned lawyer can view
    - Description is decrypted on-demand
    - Access logged
    
    Decryption Process:
    1. Retrieve encrypted blob from MongoDB
    2. Decrypt using AES-256 (requires same encryption key)
    3. Display plaintext to authorized user
    4. Log access
    """
    from bson import ObjectId
    
    try:
        request_doc = db['requests'].find_one({'_id': ObjectId(request_id)})
        
        if not request_doc:
            flash('Request not found', 'error')
            return redirect(url_for('dashboard'))
        
        # RBAC + OBJECT-LEVEL AUTHORIZATION: enforce ownership/assignment checks.
        user_id = session.get('user_id')
        if session.get('role') == 'client' and request_doc['user_id'] != user_id:
            flash('You do not have access to this request', 'error')
            return redirect(url_for('dashboard'))
        
        if session.get('role') == 'lawyer' and request_doc.get('assigned_lawyer_id') != user_id:
            flash('This request is not assigned to you', 'error')
            return redirect(url_for('dashboard'))
        
        # DECRYPTION POINT: decrypt only for authorized viewer at request time.
        if 'description_encrypted' in request_doc:
            try:
                request_doc['description'] = encryption_manager.decrypt(
                    request_doc['description_encrypted']
                )
            except:
                request_doc['description'] = '[Decryption failed]'
        
        # Log access
        auth_manager._log_action(
            session['email'],
            'REQUEST_VIEWED',
            f'Request {request_id} accessed'
        )
        
        request_doc['_id'] = str(request_doc['_id'])
        return render_template('view_request.html', request=request_doc)
    
    except Exception as e:
        flash(f'Error viewing request: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


# ============================================================================
# LAWYER ROUTES - Respond to requests
# ============================================================================

@app.route('/respond-request/<request_id>', methods=['GET', 'POST'])
@login_required
def respond_request(request_id):
    """
    Lawyer responds to legal request
    
    Security Features:
    - Only assigned lawyer can respond
    - Response is logged
    - Status update is tracked
    """
    from bson import ObjectId
    
    # RBAC ENFORCEMENT: only lawyer role can submit legal responses.
    if session.get('role') != 'lawyer':
        flash('Only lawyers can respond to requests', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        request_doc = db['requests'].find_one({'_id': ObjectId(request_id)})
        
        if not request_doc:
            flash('Request not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if assigned to this lawyer
        if request_doc.get('assigned_lawyer_id') != session.get('user_id'):
            flash('This request is not assigned to you', 'error')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            response_text = request.form.get('response', '').strip()
            status = request.form.get('status', 'in_progress')
            
            # SECURITY VALIDATION: minimum response length protects against empty/low-value submissions.
            if not response_text or len(response_text) < 10:
                flash('Response must be at least 10 characters', 'error')
                return redirect(url_for('respond_request', request_id=request_id))
            
            # Create response document
            response_doc = {
                'request_id': request_id,
                'lawyer_id': session.get('user_id'),
                'lawyer_email': session.get('email'),
                'response_text': response_text,
                'created_at': datetime.utcnow()
            }
            
            # Insert response
            db['responses'].insert_one(response_doc)
            
            # Update request status
            db['requests'].update_one(
                {'_id': ObjectId(request_id)},
                {
                    '$set': {
                        'status': status,
                        'updated_at': datetime.utcnow()
                    }
                }
            )
            
            # Log action
            auth_manager._log_action(
                session['email'],
                'REQUEST_RESPONDED',
                f'Lawyer responded to request {request_id}'
            )
            
            flash('Response submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        # Decrypt description
        if 'description_encrypted' in request_doc:
            try:
                request_doc['description'] = encryption_manager.decrypt(
                    request_doc['description_encrypted']
                )
            except:
                request_doc['description'] = '[Decryption failed]'
        
        request_doc['_id'] = str(request_doc['_id'])
        return render_template('respond_request.html', request=request_doc)
    
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


# ============================================================================
# ADMIN ROUTES - Manage users and system
# ============================================================================

@app.route('/admin/users')
@admin_required
def admin_users():
    """
    Admin: View and manage all users
    
    RBAC: Only admins can access
    """
    # RBAC ENFORCEMENT: @admin_required decorator blocks non-admin users.
    users = list(db['users'].find({}, {'password': 0}))  # Exclude password field
    
    for user in users:
        user['_id'] = str(user['_id'])
    
    return render_template('admin_users.html', users=users)


@app.route('/admin/update-role/<user_id>', methods=['POST'])
@admin_required
def update_user_role(user_id):
    """Admin: Update user role for RBAC management."""
    from bson import ObjectId

    new_role = request.form.get('role', '').strip().lower()
    if new_role not in ['client', 'lawyer', 'admin']:
        flash('Invalid role selected', 'error')
        return redirect(url_for('admin_users'))

    try:
        target_user = db['users'].find_one({'_id': ObjectId(user_id)}, {'email': 1, 'role': 1})
        if not target_user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))

        allowed_admin_email = app.config.get('ADMIN_ALLOWED_EMAIL', 'admin@example.com')
        target_email = target_user.get('email', '').strip().lower()

        # Only the whitelisted admin email can hold admin role.
        if new_role == 'admin' and target_email != allowed_admin_email:
            flash('Only the authorized admin email can have admin role.', 'error')
            return redirect(url_for('admin_users'))

        # Prevent demoting the whitelisted admin from admin role.
        if target_email == allowed_admin_email and new_role != 'admin':
            flash('Authorized admin account role cannot be changed.', 'error')
            return redirect(url_for('admin_users'))

        db['users'].update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'role': new_role, 'updated_at': datetime.utcnow()}}
        )
        auth_manager._log_action(
            session['email'],
            'USER_ROLE_UPDATED',
            f'User {user_id} role changed to {new_role}'
        )
        flash('User role updated successfully', 'success')
    except Exception as e:
        flash(f'Failed to update role: {str(e)}', 'error')

    return redirect(url_for('admin_users'))


@app.route('/admin/add-lawyer', methods=['GET', 'POST'])
@admin_required
def admin_add_lawyer():
    """
    Admin: Add new lawyer to system
    
    Security Features:
    - Input validation
    - Password hashing
    - Activity logged
    """
    if request.method == 'POST':
        data = request.form
        
        # Validate input
        is_valid, error_msg = validate_input(data, ['name', 'email', 'password', 'specialization'])
        if not is_valid:
            flash(error_msg, 'error')
            return redirect(url_for('admin_add_lawyer'))
        
        # Check password strength
        if len(data['password']) < app.config['PASSWORD_MIN_LENGTH']:
            flash(f"Password must be at least {app.config['PASSWORD_MIN_LENGTH']} characters", 'error')
            return redirect(url_for('admin_add_lawyer'))
        
        # Register lawyer
        result = auth_manager.register_user(
            name=data['name'],
            email=data['email'],
            password=data['password'],
            role='lawyer'
        )
        
        if result['success']:
            # Add lawyer details
            db['lawyers'].insert_one({
                'user_id': result['user_id'],
                'name': data['name'],
                'email': data['email'],
                'specialization': data['specialization'],
                'created_at': datetime.utcnow()
            })
            
            flash(f'Lawyer {data["name"]} added successfully!', 'success')
            
            # Log action
            auth_manager._log_action(
                session['email'],
                'LAWYER_ADDED',
                f'New lawyer added: {data["email"]}'
            )
            
            return redirect(url_for('admin_users'))
        else:
            flash(result['message'], 'error')
            return redirect(url_for('admin_add_lawyer'))
    
    return render_template('admin_add_lawyer.html')


@app.route('/admin/logs')
@admin_required
def admin_logs():
    """
    Admin: View activity logs
    
    Security Information:
    - All user actions are logged
    - Login attempts (success/failure) tracked
    - Request submissions logged
    - Response actions tracked
    - System provides audit trail
    """
    logs = list(db['logs'].find().sort('timestamp', -1).limit(100))
    
    for log in logs:
        log['_id'] = str(log['_id'])
        log['timestamp_str'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('admin_logs.html', logs=logs, recent_logs=logs)


@app.route('/admin/deactivate-user/<user_id>', methods=['POST'])
@admin_required
def deactivate_user(user_id):
    """
    Admin: Deactivate user account
    
    Security Note:
    - Sets is_active to False instead of deleting (soft delete)
    - Preserves historical data for auditing
    """
    from bson import ObjectId
    
    try:
        db['users'].update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_active': False}}
        )
        
        flash('User deactivated successfully', 'success')
        
        auth_manager._log_action(
            session['email'],
            'USER_DEACTIVATED',
            f'User {user_id} deactivated'
        )
    except:
        flash('Error deactivating user', 'error')
    
    return redirect(url_for('admin_users'))


@app.route('/admin/activate-user/<user_id>', methods=['POST'])
@admin_required
def activate_user(user_id):
    """Admin: Reactivate previously deactivated user account."""
    from bson import ObjectId

    try:
        db['users'].update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_active': True, 'failed_login_attempts': 0, 'lockout_until': None}}
        )
        auth_manager._log_action(
            session['email'],
            'USER_ACTIVATED',
            f'User {user_id} activated'
        )
        flash('User activated successfully', 'success')
    except Exception:
        flash('Error activating user', 'error')

    return redirect(url_for('admin_users'))


@app.route('/admin/requests')
@admin_required
def admin_requests():
    """Admin: View all legal requests and assignment status."""
    requests_data = list(db['requests'].find().sort('created_at', -1))
    lawyers = list(db['users'].find({'role': 'lawyer', 'is_active': True}, {'name': 1, 'email': 1}))

    lawyer_map = {str(l['_id']): l for l in lawyers}

    for req in requests_data:
        req['_id'] = str(req['_id'])
        assigned_id = req.get('assigned_lawyer_id')
        req['assigned_lawyer_name'] = lawyer_map.get(assigned_id, {}).get('name', 'Unassigned') if assigned_id else 'Unassigned'

    for lawyer in lawyers:
        lawyer['_id'] = str(lawyer['_id'])

    return render_template('admin_requests.html', requests=requests_data, lawyers=lawyers)


@app.route('/admin/assign-lawyer/<request_id>', methods=['POST'])
@admin_required
def assign_lawyer(request_id):
    """Admin: Assign lawyer to a request."""
    from bson import ObjectId

    lawyer_id = request.form.get('lawyer_id', '').strip()
    if not lawyer_id:
        flash('Please select a lawyer', 'error')
        return redirect(url_for('admin_requests'))

    try:
        db['requests'].update_one(
            {'_id': ObjectId(request_id)},
            {
                '$set': {
                    'assigned_lawyer_id': lawyer_id,
                    'status': 'in_progress',
                    'updated_at': datetime.utcnow()
                }
            }
        )
        auth_manager._log_action(
            session['email'],
            'LAWYER_ASSIGNED',
            f'Lawyer {lawyer_id} assigned to request {request_id}'
        )
        flash('Lawyer assigned successfully', 'success')
    except Exception as e:
        flash(f'Failed to assign lawyer: {str(e)}', 'error')

    return redirect(url_for('admin_requests'))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('error.html', 
                         error_code=404,
                         error_message='Page not found'), 404


@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors (forbidden access)"""
    return render_template('error.html',
                         error_code=403,
                         error_message='Access denied. You do not have permission.'), 403


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    auth_manager._log_action(
        session.get('email', 'unknown'),
        'SERVER_ERROR',
        str(error)
    )
    
    return render_template('error.html',
                         error_code=500,
                         error_message='Internal server error'), 500


# ============================================================================
# CLI COMMANDS - Setup and management
# ============================================================================

def initialize_database():
    """Initialize database with collections and indexes."""
    try:
        # Create collections
        collections = ['users', 'lawyers', 'requests', 'responses', 'logs']
        existing = db.list_collection_names()
        
        for collection in collections:
            if collection not in existing:
                db.create_collection(collection)
                print(f"✓ Created collection: {collection}")
        
        # Create indexes for performance
        db['users'].create_index('email', unique=True)
        db['requests'].create_index('user_id')
        db['requests'].create_index('assigned_lawyer_id')
        db['responses'].create_index('request_id')
        db['logs'].create_index('timestamp')
        
        print("✓ Database initialized successfully!")
        print("✓ Indexes created")
    
    except Exception as e:
        print(f"✗ Error initializing database: {str(e)}")


@app.cli.command()
def init_db():
    """Initialize database with collections and indexes"""
    initialize_database()


@app.cli.command()
def create_admin():
    """Create admin user"""
    email = input("Admin email: ")
    name = input("Admin name: ")
    password = input("Admin password: ")

    allowed_admin_email = app.config.get('ADMIN_ALLOWED_EMAIL', 'admin@example.com')
    if email.strip().lower() != allowed_admin_email:
        print(f"✗ Only {allowed_admin_email} is allowed as admin email")
        return
    
    result = auth_manager.register_user(name, email, password, role='admin')
    
    if result['success']:
        print(f"✓ Admin created successfully!")
        print(f"  Email: {email}")
        print(f"  User ID: {result['user_id']}")
    else:
        print(f"✗ Failed: {result['message']}")


if __name__ == '__main__':
    # Initialize database on first run
    if 'requests' not in db.list_collection_names():
        print("Initializing database...")
        with app.app_context():
            initialize_database()
    
    # Run Flask development server
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)
