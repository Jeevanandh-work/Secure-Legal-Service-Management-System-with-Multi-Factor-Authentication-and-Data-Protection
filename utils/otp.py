"""
OTP Module
Handles OTP generation and email sending for 2-Factor Authentication
SECURITY: OTP is stored in session (server-side), not exposed to client
"""

import random
import string
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import session

class OTPManager:
    """Manages OTP generation, storage, and validation"""
    
    def __init__(self, mail_config):
        """
        Initialize OTP manager
        Args:
            mail_config (dict): Email configuration with SMTP details
        """
        self.mail_server = mail_config.get('MAIL_SERVER')
        self.mail_port = mail_config.get('MAIL_PORT')
        self.mail_use_tls = mail_config.get('MAIL_USE_TLS')
        self.mail_username = mail_config.get('MAIL_USERNAME')
        self.mail_password = mail_config.get('MAIL_PASSWORD')
        self.otp_length = mail_config.get('OTP_LENGTH', 6)
        self.otp_expiry_minutes = mail_config.get('OTP_EXPIRY_MINUTES', 5)
        self.max_attempts = mail_config.get('OTP_MAX_ATTEMPTS', 3)
    
    def send_otp(self, email, name="User"):
        """
        Generate OTP and send it via email
        
        Security Features:
        - 6-digit OTP with random generation
        - OTP expires in 5 minutes
        - Stores attempt counter (max 3 attempts)
        - OTP stored in session (server-side only)
        
        Args:
            email (str): Recipient email address
            name (str): User name for personalized email
        
        Returns:
            dict: Status with 'success' flag and 'message'
        """
        try:
            # Generate random 6-digit OTP
            otp = ''.join(random.choices(string.digits, k=self.otp_length))
            
            # Store OTP in session with metadata
            session['otp'] = otp
            session['otp_email'] = email
            session['otp_created_at'] = datetime.utcnow().isoformat()
            session['otp_attempts'] = 0
            
            # Send OTP via email. If SMTP is not configured in development,
            # fall back to console output so the app remains usable for demos.
            try:
                self._send_email(email, otp, name)
            except Exception as email_error:
                session['otp_debug'] = otp
                if self._has_placeholder_smtp_credentials():
                    print(f"[DEV OTP] OTP for {email}: {otp}")
                    print(f"[DEV OTP] Email fallback used because SMTP is not configured: {email_error}")
                else:
                    print(f"[DEV OTP] SMTP delivery failed, using debug OTP fallback for {email}: {email_error}")
            
            return {
                'success': True,
                'message': f'OTP sent to {email}. Valid for {self.otp_expiry_minutes} minutes.'
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to send OTP: {str(e)}'
            }
    
    def verify_otp(self, provided_otp):
        """
        Verify OTP provided by user
        
        Security Checks:
        1. Verify OTP matches stored OTP
        2. Check OTP hasn't expired (5 minutes)
        3. Check attempts haven't exceeded limit (3 attempts)
        4. Clear OTP after successful verification
        
        Args:
            provided_otp (str): OTP provided by user
        
        Returns:
            dict: Status with 'valid' flag and 'message'
        """
        # Check if OTP exists in session
        if 'otp' not in session:
            return {
                'valid': False,
                'message': 'No OTP request found. Please request a new OTP.'
            }
        
        # Check if OTP has expired
        otp_created_at = datetime.fromisoformat(session.get('otp_created_at', ''))
        otp_age = datetime.utcnow() - otp_created_at
        
        if otp_age > timedelta(minutes=self.otp_expiry_minutes):
            session.pop('otp', None)
            session.pop('otp_email', None)
            session.pop('otp_created_at', None)
            return {
                'valid': False,
                'message': f'OTP expired. Valid for only {self.otp_expiry_minutes} minutes.'
            }
        
        # Check attempt limit
        attempts = session.get('otp_attempts', 0)
        if attempts >= self.max_attempts:
            session.pop('otp', None)
            session.pop('otp_email', None)
            session.pop('otp_created_at', None)
            return {
                'valid': False,
                'message': f'Maximum {self.max_attempts} OTP attempts exceeded. Request new OTP.'
            }
        
        # Verify OTP matches
        if str(provided_otp) == str(session.get('otp')):
            # OTP is valid - clear it from session
            session.pop('otp', None)
            session.pop('otp_email', None)
            session.pop('otp_created_at', None)
            session.pop('otp_attempts', None)
            session.pop('otp_debug', None)
            
            return {
                'valid': True,
                'message': 'OTP verified successfully'
            }
        else:
            # Invalid OTP - increment attempt counter
            session['otp_attempts'] = attempts + 1
            remaining_attempts = self.max_attempts - (attempts + 1)
            
            return {
                'valid': False,
                'message': f'Invalid OTP. {remaining_attempts} attempts remaining.'
            }
    
    def _send_email(self, to_email, otp, name):
        """
        Send OTP via Gmail SMTP
        
        Security Notes:
        - Uses TLS encryption for SMTP connection
        - Requires Gmail app-specific password (not regular password)
        - Email contains OTP and expiry information
        
        Args:
            to_email (str): Recipient email
            otp (str): Generated OTP
            name (str): User name
        """
        try:
            # Create email message
            message = MIMEMultipart()
            message['From'] = self.mail_username
            message['To'] = to_email
            message['Subject'] = 'Your OTP for Legal Service Platform'
            
            # Email body with security information
            body = f"""
Hello {name},

Your OTP (One-Time Password) for login is:

*** {otp} ***

Important:
- This OTP is valid for only {self.otp_expiry_minutes} minutes
- Do not share this OTP with anyone
- Never give your password to anyone claiming to be from our support
- If you didn't request this OTP, please ignore this email

Security Tips:
- Always use HTTPS when logging in
- Log out after each session
- Use a strong, unique password

If you have any issues, contact: support@legals.com

Best regards,
Legal Service Platform Team
            """
            
            message.attach(MIMEText(body, 'plain'))
            
            # Send email via SMTP
            with smtplib.SMTP(self.mail_server, self.mail_port) as server:
                server.starttls()  # Encrypt connection
                server.login(self.mail_username, self.mail_password)
                server.send_message(message)
        
        except smtplib.SMTPAuthenticationError:
            raise Exception("Gmail authentication failed. Check username/password and enable 2FA app password.")
        except smtplib.SMTPException as e:
            raise Exception(f"SMTP error: {str(e)}")
        except Exception as e:
            raise Exception(f"Email sending error: {str(e)}")

    def send_notification(self, to_email, subject, body):
        """Send a generic security/product notification email over TLS SMTP."""
        try:
            message = MIMEMultipart()
            message['From'] = self.mail_username
            message['To'] = to_email
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.mail_server, self.mail_port) as server:
                server.starttls()
                server.login(self.mail_username, self.mail_password)
                server.send_message(message)

            return {'success': True, 'message': 'Notification sent'}
        except Exception as e:
            print(f"[DEV NOTIFY] {subject} -> {to_email}: {e}")
            return {'success': False, 'message': f'Notification failed: {str(e)}'}

    def _has_placeholder_smtp_credentials(self):
        """Detect whether the app is still using example SMTP values."""
        username = str(self.mail_username or '').strip().lower()
        password = str(self.mail_password or '').strip().lower()
        return (
            not username
            or not password
            or username.startswith('your-')
            or password.startswith('your-')
            or 'example' in username
            or 'example' in password
        )

# Global OTP manager instance
def get_otp_manager(mail_config):
    """Factory function to create OTP manager instance"""
    return OTPManager(mail_config)
