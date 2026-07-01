"""
Authentication Module
Handles user authentication, password hashing, and role-based access control
SECURITY: All passwords are hashed using bcrypt (never stored in plain text)
"""

import bcrypt
import os
from functools import wraps
from flask import session, redirect, url_for, abort, request, current_app
from pymongo import MongoClient
from datetime import datetime, timedelta

class AuthManager:
    """Manages user authentication and authorization"""
    
    def __init__(self, db, hash_rounds=12, max_failed_attempts=5, lockout_minutes=5):
        """
        Initialize authentication manager
        
        Args:
            db: MongoDB database instance
            hash_rounds (int): bcrypt rounds for password hashing (higher = more secure)
            max_failed_attempts (int): failed login attempts before temporary lockout
            lockout_minutes (int): lockout duration in minutes
        """
        self.db = db
        self.hash_rounds = hash_rounds
        self.max_failed_attempts = max_failed_attempts
        self.lockout_minutes = lockout_minutes
        self.users_collection = db['users']
        self.logs_collection = db['logs']
    
    def hash_password(self, password):
        """
        Hash password using bcrypt
        
        Security Notes:
        - Uses bcrypt with 12 rounds (configurable)
        - Each password is salted automatically
        - No two identical passwords will produce same hash
        - Password is irreversible (cannot be decrypted)
        
        Args:
            password (str): Plain text password
        
        Returns:
            str: Bcrypt hashed password
        """
        try:
            # Generate salt and hash password
            salt = bcrypt.gensalt(rounds=self.hash_rounds)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        except Exception as e:
            raise Exception(f"Password hashing failed: {str(e)}")
    
    def verify_password(self, password, hashed_password):
        """
        Verify plain text password against bcrypt hash
        
        Security Notes:
        - Uses constant-time comparison to prevent timing attacks
        - Safe to use even with wrong number of rounds
        - Returns False if password doesn't match
        
        Args:
            password (str): Plain text password to verify
            hashed_password (str): Bcrypt hashed password from database
        
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception:
            return False
    
    def register_user(self, name, email, password, role='client'):
        """
        Register new user with secure password hashing
        
        Security Checks:
        1. Verify email doesn't already exist
        2. Validate password strength (minimum 8 characters)
        3. Hash password using bcrypt
        4. Store user with hashed password
        5. Log registration action
        
        Args:
            name (str): User's full name
            email (str): User's email
            password (str): Plain text password
            role (str): User role (client/lawyer/admin)
        
        Returns:
            dict: Status with 'success' flag and 'message'
        """
        try:
            normalized_email = (email or '').strip().lower()
            allowed_admin_email = os.environ.get('ADMIN_ALLOWED_EMAIL', 'admin@example.com').strip().lower()

            if role == 'admin' and normalized_email != allowed_admin_email:
                return {
                    'success': False,
                    'message': 'Only the authorized admin email can be assigned admin role.'
                }

            # Check if user already exists
            existing_user = self.users_collection.find_one({'email': email})
            if existing_user:
                return {
                    'success': False,
                    'message': 'Email already registered. Please login or use different email.'
                }
            
            # Validate password strength
            if len(password) < 8:
                return {
                    'success': False,
                    'message': 'Password must be at least 8 characters long'
                }
            
            # Hash password
            hashed_password = self.hash_password(password)
            
            # Create user document
            user_document = {
                'name': name,
                'email': email,
                'password': hashed_password,  # NEVER store plain text
                'role': role,
                'created_at': datetime.utcnow(),
                'is_active': True,
                'failed_login_attempts': 0,
                'lockout_until': None
            }
            
            # Insert into database
            result = self.users_collection.insert_one(user_document)
            
            # Log registration
            self._log_action(email, f'USER_REGISTERED', f'New {role} registered')
            
            return {
                'success': True,
                'message': f'Registration successful. User ID: {str(result.inserted_id)}',
                'user_id': str(result.inserted_id)
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Registration failed: {str(e)}'
            }
    
    def authenticate_user(self, email, password):
        """
        Authenticate user by email and password
        
        Security Process:
        1. Find user by email
        2. Verify password using bcrypt secure comparison
        3. Log login attempt (success or failure)
        4. Return user data if successful
        
        Args:
            email (str): User email
            password (str): Plain text password
        
        Returns:
            dict: Status with user data if successful
        """
        try:
            # Find user by email
            user = self.users_collection.find_one({'email': email, 'is_active': True})
            
            if not user:
                # Log failed login attempt
                self._log_action(email, 'LOGIN_FAILED', 'User not found')
                return {
                    'success': False,
                    'message': 'Invalid email or password'
                }
            
            # Enforce account lockout window after repeated failures
            if user.get('lockout_until') and datetime.utcnow() < user['lockout_until']:
                self._log_action(email, 'LOGIN_BLOCKED', 'Account temporarily locked due to failed attempts')
                return {
                    'success': False,
                    'message': f'Account is temporarily locked. Try again after {user["lockout_until"].strftime("%H:%M:%S UTC")}'
                }

            # Verify password using bcrypt
            if not self.verify_password(password, user['password']):
                failed_attempts = int(user.get('failed_login_attempts', 0)) + 1
                update_doc = {'failed_login_attempts': failed_attempts}

                if failed_attempts >= self.max_failed_attempts:
                    lockout_until = datetime.utcnow() + timedelta(minutes=self.lockout_minutes)
                    update_doc['lockout_until'] = lockout_until
                    self._log_action(email, 'ACCOUNT_LOCKED', f'Locked for {self.lockout_minutes} minutes after repeated failures')

                self.users_collection.update_one({'_id': user['_id']}, {'$set': update_doc})

                # Log failed login attempt
                self._log_action(email, 'LOGIN_FAILED', 'Invalid password')
                return {
                    'success': False,
                    'message': 'Invalid email or password'
                }

            # Reset failed counter on successful password verification
            self.users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'failed_login_attempts': 0, 'lockout_until': None}}
            )
            
            # Log successful login attempt
            self._log_action(email, 'LOGIN_SUCCESS', 'User authenticated')
            
            # Return user data (exclude password hash)
            return {
                'success': True,
                'message': 'Authentication successful',
                'user': {
                    'id': str(user['_id']),
                    'name': user['name'],
                    'email': user['email'],
                    'role': user['role']
                }
            }
        
        except Exception as e:
            self._log_action(email, 'LOGIN_ERROR', f'Error: {str(e)}')
            return {
                'success': False,
                'message': f'Authentication error: {str(e)}'
            }

    def change_password(self, user_id, current_password, new_password):
        """Change user password after verifying current password."""
        try:
            user = self.users_collection.find_one({'_id': user_id, 'is_active': True})
            if not user:
                return {'success': False, 'message': 'User not found'}

            if not self.verify_password(current_password, user['password']):
                self._log_action(user['email'], 'PASSWORD_CHANGE_FAILED', 'Current password mismatch')
                return {'success': False, 'message': 'Current password is incorrect'}

            if len(new_password) < 8:
                return {'success': False, 'message': 'New password must be at least 8 characters long'}

            new_hash = self.hash_password(new_password)
            self.users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'password': new_hash, 'updated_at': datetime.utcnow()}}
            )

            self._log_action(user['email'], 'PASSWORD_CHANGED', 'Password changed successfully')
            return {'success': True, 'message': 'Password changed successfully', 'email': user['email'], 'name': user.get('name', 'User')}
        except Exception as e:
            return {'success': False, 'message': f'Password change failed: {str(e)}'}
    
    def _log_action(self, user_email, action, details):
        """
        Log user action (login, registration, etc.)
        
        Security Note:
        - Every important action is logged with timestamp
        - Admin can review logs for suspicious activity
        - Includes IP address info in production
        
        Args:
            user_email (str): User email
            action (str): Action type (LOGIN_SUCCESS, LOGIN_FAILED, etc.)
            details (str): Additional details about action
        """
        try:
            log_entry = {
                'user': user_email,
                'action': action,
                'details': details,
                'timestamp': datetime.utcnow(),
                'ip_address': request.remote_addr if request else 'unknown'
            }
            self.logs_collection.insert_one(log_entry)
        except Exception:
            pass  # Don't fail main operation if logging fails


def login_required(f):
    """
    Decorator to protect routes that require login
    Redirects to login page if user is not authenticated
    
    Usage:
        @app.route('/dashboard')
        @login_required
        def dashboard():
            return render_template('dashboard.html')
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorator to protect routes that require admin role
    Returns 403 Forbidden if user is not admin
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        if session.get('role') != 'admin':
            abort(403)

        allowed_admin_email = current_app.config.get('ADMIN_ALLOWED_EMAIL', 'admin@example.com').strip().lower()
        if session.get('email', '').strip().lower() != allowed_admin_email:
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function


def lawyer_required(f):
    """
    Decorator to protect routes that require lawyer role
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        if session.get('role') not in ['lawyer', 'admin']:
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function


# Input validation helper
def validate_input(data, required_fields):
    """
    Validate user input to prevent injection attacks
    
    Security Note:
    - Checks required fields exist
    - Validates email format
    - Checks string length
    
    Args:
        data (dict): Input data to validate
        required_fields (list): List of required field names
    
    Returns:
        tuple: (is_valid, error_message)
    """
    # Check required fields
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing required field: {field}"
    
    # Validate email format if email field exists
    if 'email' in data:
        email = data['email']
        if '@' not in email or '.' not in email:
            return False, "Invalid email format"
        if len(email) > 120:
            return False, "Email too long"
    
    # Check string lengths (prevent huge payloads)
    for key, value in data.items():
        if isinstance(value, str) and len(value) > 10000:
            return False, f"Field {key} exceeds maximum length"
    
    return True, ""
