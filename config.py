"""
Configuration Module
Stores all sensitive configuration including database, email, and encryption settings
SECURITY NOTE: In production, use environment variables instead of hardcoding credentials
"""

import os
from datetime import timedelta


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_encryption_key():
    """Load a 32-byte AES key from the environment or use a safe default."""
    key_value = os.environ.get('ENCRYPTION_KEY')

    if key_value:
        key_bytes = key_value.encode('utf-8')
        if len(key_bytes) == 32:
            return key_bytes

    return b'0123456789abcdef0123456789abcdef'

class Config:
    """Base configuration class with security settings"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
    SESSION_COOKIE_SECURE = True  # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript from accessing session cookies
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # Session timeout
    
    # MongoDB Atlas Configuration (Secure Connection with TLS)
    # Format: mongodb+srv://username:password@cluster0.mongodb.net/database?retryWrites=true&w=majority&tls=true
    MONGO_URI = os.environ.get('MONGO_URI', 
        'mongodb+srv://admin:password@cluster0.mongodb.net/legal_service?retryWrites=true&w=majority&tls=true')
    
    # Encryption Configuration
    # AES encryption key (32 bytes = 256-bit encryption)
    # SECURITY NOTE: Store this in a key management system in production
    ENCRYPTION_KEY = _load_encryption_key()

    # OTP payload encryption key (AES-256). Reuses ENCRYPTION_KEY if not explicitly set.
    OTP_ENCRYPTION_KEY = os.environ.get('OTP_ENCRYPTION_KEY', ENCRYPTION_KEY.decode('utf-8'))

    # RSA key paths for hybrid encryption demo.
    RSA_PRIVATE_KEY_PATH = os.environ.get('RSA_PRIVATE_KEY_PATH', os.path.join(BASE_DIR, 'keys', 'rsa_private.pem'))
    RSA_PUBLIC_KEY_PATH = os.environ.get('RSA_PUBLIC_KEY_PATH', os.path.join(BASE_DIR, 'keys', 'rsa_public.pem'))

    # Per-user digital signature key directory.
    SIGNATURE_KEYS_DIR = os.environ.get('SIGNATURE_KEYS_DIR', os.path.join(BASE_DIR, 'keys', 'signatures'))

    # Diffie-Hellman demonstration switch.
    ENABLE_DH_DEMO = os.environ.get('ENABLE_DH_DEMO', 'true').strip().lower() == 'true'

    # HTTPS certificate support (self-signed cert in demo).
    SSL_CERT_FILE = os.environ.get('SSL_CERT_FILE', os.path.join(BASE_DIR, 'certs', 'cert.pem'))
    SSL_KEY_FILE = os.environ.get('SSL_KEY_FILE', os.path.join(BASE_DIR, 'certs', 'key.pem'))
    ENABLE_HTTPS = os.environ.get('ENABLE_HTTPS', 'false').strip().lower() == 'true'
    
    # Email Configuration (Gmail SMTP for OTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'your-app-password')
    MAIL_DEFAULT_SENDER = MAIL_USERNAME
    
    # OTP Configuration
    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 5  # OTP valid for 5 minutes
    OTP_MAX_ATTEMPTS = 3  # Maximum OTP verification attempts
    
    # Security Settings
    PASSWORD_MIN_LENGTH = 8
    HASH_ROUNDS = 12  # bcrypt rounds (higher = slower but more secure)
    LOGIN_MAX_FAILED_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 5
    ADMIN_ALLOWED_EMAIL = os.environ.get('ADMIN_ALLOWED_EMAIL', 'admin@example.com').strip().lower()

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SESSION_COOKIE_SECURE = False

# Select configuration based on environment
config_name = os.environ.get('FLASK_ENV', 'development')
if config_name == 'production':
    app_config = ProductionConfig
elif config_name == 'testing':
    app_config = TestingConfig
else:
    app_config = DevelopmentConfig
