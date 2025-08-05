from app.database import db
from app.config import settings
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import secrets
import hashlib
from fastapi import BackgroundTasks
class ResetTokenCRUD:
    def __init__(self):
        
        if db.password_reset_tokens_col is None:
            raise RuntimeError("Password reset tokens collection not initialized")
        self.password_reset_tokens_collection = db.password_reset_tokens_col

    async def create_reset_token(self, email: str) -> str:
        """Create a new password reset token"""
        # Invalidate any existing tokens for this email
        await self.password_reset_tokens_collection.update_many(
            {"email": email, "used": False},
            {"$set": {"used": True}}
        )
        
        # Generate new token
        token = self.generate_reset_token()
        token_hash = self.hash_token(token)
        expires_at = datetime.utcnow() + timedelta(hours=settings.TOKEN_EXPIRY_HOURS)
        
        # Save token to database
        token_doc = {
            "email": email,
            "token_hash": token_hash,
            "expires_at": expires_at,
            "used": False,
            "created_at": datetime.utcnow()
        }
        
        await self.password_reset_tokens_collection.insert_one(token_doc)
        
        return token

    
    @staticmethod
    def generate_reset_token() -> str:
        """Generate a secure random token for password reset"""
        return secrets.token_urlsafe(settings.TOKEN_LENGTH)
    @staticmethod
    def hash_token(token: str) -> str:
        """Hash token for secure storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    @staticmethod
    def send_reset_email(email: str, token: str, background_tasks: BackgroundTasks):
        """Send password reset email with token"""
        def send_email():
            try:
                # Create message
                msg = MIMEMultipart('alternative')
                msg['Subject'] = "LeakSight - Password Reset Request"
                msg['From'] = settings.FROM_EMAIL
                msg['To'] = email
                
                # Reset URL
                reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
                
                # Create HTML content
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <title>Password Reset - LeakSight</title>
                    <style>
                        body {{
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            line-height: 1.6;
                            color: #e0e0e0;
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #0a0a0a;
                        }}
                        .email-container {{
                            background-color: #1a1a2e;
                            border-radius: 12px;
                            overflow: hidden;
                            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
                        }}
                        .header {{
                            background: linear-gradient(135deg, #16213e 0%, #0f3460 100%);
                            color: white;
                            padding: 30px 20px;
                            text-align: center;
                            position: relative;
                        }}
                        .header::before {{
                            content: '';
                            position: absolute;
                            top: 0;
                            left: 0;
                            right: 0;
                            bottom: 0;
                            background: radial-gradient(circle at 50% 50%, rgba(125, 230, 231, 0.1) 0%, transparent 70%);
                        }}
                        .logo {{
                            font-size: 2.5em;
                            margin-bottom: 10px;
                            position: relative;
                            z-index: 1;
                        }}
                        .logo-icon {{
                            color: #7de6e7;
                            margin-right: 10px;
                        }}
                        .logo-text {{
                            color: #7de6e7;
                            font-weight: bold;
                        }}
                        .header h2 {{
                            margin: 0;
                            font-size: 1.4em;
                            font-weight: 300;
                            position: relative;
                            z-index: 1;
                        }}
                        .content {{
                            background-color: #1a1a2e;
                            padding: 40px 30px;
                            color: #e0e0e0;
                        }}
                        .content p {{
                            margin: 15px 0;
                            font-size: 16px;
                        }}
                        .button {{
                            display: inline-block;
                            background: linear-gradient(135deg, #7de6e7 0%, #0f3460 100%);
                            color: #1a1a2e;
                            padding: 15px 35px;
                            text-decoration: none;
                            border-radius: 8px;
                            margin: 25px 0;
                            font-weight: bold;
                            font-size: 16px;
                            transition: all 0.3s ease;
                            box-shadow: 0 4px 15px rgba(125, 230, 231, 0.3);
                        }}
                        .button:hover {{
                            transform: translateY(-2px);
                            box-shadow: 0 6px 20px rgba(125, 230, 231, 0.4);
                        }}
                        .reset-link {{
                            word-break: break-all;
                            color: #7de6e7;
                            background-color: #16213e;
                            padding: 12px;
                            border-radius: 6px;
                            border-left: 4px solid #7de6e7;
                            font-family: 'Courier New', monospace;
                            font-size: 14px;
                        }}
                        .warning {{
                            background-color: #16213e;
                            border: 1px solid #f39c12;
                            border-left: 4px solid #f39c12;
                            color: #e0e0e0;
                            padding: 20px;
                            border-radius: 8px;
                            margin: 25px 0;
                        }}
                        .warning strong {{
                            color: #f39c12;
                            display: block;
                            margin-bottom: 10px;
                        }}
                        .warning ul {{
                            margin: 10px 0;
                            padding-left: 20px;
                        }}
                        .warning li {{
                            margin: 8px 0;
                        }}
                        .footer {{
                            background-color: #16213e;
                            margin-top: 0;
                            padding: 25px 30px;
                            border-top: 1px solid #0f3460;
                            font-size: 13px;
                            color: #a0a0a0;
                            text-align: center;
                        }}
                        .footer p {{
                            margin: 8px 0;
                        }}
                        .security-badge {{
                            display: inline-block;
                            background-color: #0f3460;
                            color: #7de6e7;
                            padding: 8px 15px;
                            border-radius: 20px;
                            font-size: 12px;
                            font-weight: bold;
                            margin-top: 15px;
                        }}
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <div class="logo">
                                <span class="logo-icon">🛡️</span>
                                <span class="logo-text">LeakSight</span>
                            </div>
                            <h2>Password Reset Request</h2>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>We received a request to reset your password for your LeakSight account. If you made this request, click the button below to reset your password:</p>
                            
                            <div style="text-align: center;">
                                <a href="{reset_url}" class="button">Reset Password</a>
                            </div>
                            
                            <p>Or copy and paste this link into your browser:</p>
                            <div class="reset-link">{reset_url}</div>
                            
                            <div class="warning">
                                <strong>⚠️ Security Notice:</strong>
                                <ul>
                                    <li>This link will expire in {settings.TOKEN_EXPIRY_HOURS} hour(s)</li>
                                    <li>If you didn't request this reset, please ignore this email</li>
                                    <li>For security, this link can only be used once</li>
                                    <li>Never share this link with anyone</li>
                                </ul>
                            </div>
                            
                            <p>If you have any questions or concerns, please contact our support team immediately.</p>
                            
                            <p>Best regards,<br><strong>The LeakSight Security Team</strong></p>
                            
                            <div style="text-align: center;">
                                <div class="security-badge">🔒 Secure • Encrypted • Protected</div>
                            </div>
                        </div>
                        <div class="footer">
                            <p>This is an automated message from LeakSight Threat Intelligence Platform.</p>
                            <p>If you didn't request this password reset, please contact support immediately.</p>
                            <p style="margin-top: 15px; font-size: 11px; opacity: 0.7;">
                                © 2025 LeakSight. All rights reserved.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                """
                # Create plain text version
                text_content = f"""
                LeakSight - Password Reset Request
                
                Hello,
                
                We received a request to reset your password for your LeakSight account.
                
                To reset your password, click the following link:
                {reset_url}
                
                Important:
                - This link will expire in {settings.TOKEN_EXPIRY_HOURS} hour(s)
                - If you didn't request this reset, please ignore this email
                - For security, this link can only be used once
                
                If you have any questions, please contact our support team.
                
                Best regards,
                The LeakSight Security Team
                """
                
                # Attach parts
                part1 = MIMEText(text_content, 'plain')
                part2 = MIMEText(html_content, 'html')
                
                msg.attach(part1)
                msg.attach(part2)
                
                # Send email
                with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                    server.starttls()
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    text = msg.as_string()
                    server.sendmail(settings.FROM_EMAIL, email, text)
                    
                print(f"Password reset email sent successfully to {email}")
                
            except Exception as e:
                print(f"Failed to send email to {email}: {str(e)}")
                # In production, you might want to log this error or retry
        
        background_tasks.add_task(send_email)
