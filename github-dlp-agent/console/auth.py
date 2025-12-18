#!/usr/bin/env python3
"""
Authentication Module for DLP Console
Supports Microsoft Entra (Azure AD) and Google Workspace
Cibershield R.L. 2025
"""

import os
import secrets
from functools import wraps
from flask import Blueprint, redirect, url_for, session, request, jsonify, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth

# Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

# OAuth instance
oauth = OAuth()

# Login manager
login_manager = LoginManager()


class User(UserMixin):
    """User model for Flask-Login"""

    def __init__(self, user_id, email, name, provider, avatar=None):
        self.id = user_id
        self.email = email
        self.name = name
        self.provider = provider  # 'microsoft' or 'google'
        self.avatar = avatar

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'provider': self.provider,
            'avatar': self.avatar
        }


# In-memory user store (in production, use a database)
users_db = {}


def init_auth(app):
    """Initialize authentication for the Flask app"""

    # Secret key for sessions
    app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

    # Initialize login manager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicie sesión para acceder.'

    # Initialize OAuth
    oauth.init_app(app)

    # Configure Microsoft Entra (Azure AD)
    if os.getenv('MICROSOFT_CLIENT_ID'):
        oauth.register(
            name='microsoft',
            client_id=os.getenv('MICROSOFT_CLIENT_ID'),
            client_secret=os.getenv('MICROSOFT_CLIENT_SECRET'),
            server_metadata_url=f"https://login.microsoftonline.com/{os.getenv('MICROSOFT_TENANT_ID', 'common')}/v2.0/.well-known/openid-configuration",
            client_kwargs={
                'scope': 'openid email profile'
            }
        )

    # Configure Google Workspace
    if os.getenv('GOOGLE_CLIENT_ID'):
        oauth.register(
            name='google',
            client_id=os.getenv('GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )

    # Register blueprint
    app.register_blueprint(auth_bp)

    return app


@login_manager.user_loader
def load_user(user_id):
    """Load user from session"""
    return users_db.get(user_id)


def is_auth_enabled():
    """Check if any auth provider is configured"""
    return bool(os.getenv('MICROSOFT_CLIENT_ID') or os.getenv('GOOGLE_CLIENT_ID'))


def get_configured_providers():
    """Get list of configured auth providers"""
    providers = []
    if os.getenv('MICROSOFT_CLIENT_ID'):
        providers.append('microsoft')
    if os.getenv('GOOGLE_CLIENT_ID'):
        providers.append('google')
    return providers


# ============== Auth Routes ==============

@auth_bp.route('/login')
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect('/')

    providers = get_configured_providers()

    # If no auth configured, allow access
    if not providers:
        return redirect('/')

    # Build login page HTML
    html = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - DLP Console</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', system-ui, sans-serif;
                background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #e0e0e0;
            }
            .login-container {
                background: #1a1a2e;
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.5);
                text-align: center;
                max-width: 400px;
                width: 90%;
            }
            .logo {
                font-size: 3rem;
                margin-bottom: 10px;
            }
            h1 {
                color: #00d4ff;
                font-size: 1.5rem;
                margin-bottom: 10px;
            }
            .subtitle {
                color: #888;
                font-size: 0.9rem;
                margin-bottom: 30px;
            }
            .login-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 12px;
                width: 100%;
                padding: 14px 20px;
                margin: 10px 0;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                cursor: pointer;
                text-decoration: none;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            .login-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 20px rgba(0,0,0,0.3);
            }
            .login-btn.microsoft {
                background: #2f2f2f;
                color: white;
            }
            .login-btn.google {
                background: white;
                color: #333;
            }
            .login-btn svg {
                width: 20px;
                height: 20px;
            }
            .footer {
                margin-top: 30px;
                color: #666;
                font-size: 0.8rem;
            }
            .footer strong {
                color: #00d4ff;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">🛡️</div>
            <h1>DLP Console</h1>
            <p class="subtitle">Sistema de Prevención de Pérdida de Datos</p>
    """

    if 'microsoft' in providers:
        html += """
            <a href="/auth/microsoft" class="login-btn microsoft">
                <svg viewBox="0 0 21 21" fill="none">
                    <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
                    <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
                    <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
                    <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
                </svg>
                Iniciar sesión con Microsoft
            </a>
        """

    if 'google' in providers:
        html += """
            <a href="/auth/google" class="login-btn google">
                <svg viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Iniciar sesión con Google
            </a>
        """

    html += """
            <div class="footer">
                <p>Desarrollado por <strong>Cibershield R.L.</strong> 2025</p>
            </div>
        </div>
    </body>
    </html>
    """

    return html


@auth_bp.route('/auth/microsoft')
def microsoft_login():
    """Start Microsoft OAuth flow"""
    if not os.getenv('MICROSOFT_CLIENT_ID'):
        return jsonify({'error': 'Microsoft auth not configured'}), 400

    redirect_uri = url_for('auth.microsoft_callback', _external=True)
    return oauth.microsoft.authorize_redirect(redirect_uri)


@auth_bp.route('/auth/microsoft/callback')
def microsoft_callback():
    """Handle Microsoft OAuth callback"""
    try:
        token = oauth.microsoft.authorize_access_token()
        userinfo = token.get('userinfo')

        if not userinfo:
            # Fetch user info from Microsoft Graph
            resp = oauth.microsoft.get('https://graph.microsoft.com/v1.0/me')
            userinfo = resp.json()

        user_id = userinfo.get('sub') or userinfo.get('id')
        email = userinfo.get('email') or userinfo.get('mail') or userinfo.get('userPrincipalName')
        name = userinfo.get('name') or userinfo.get('displayName')

        # Create user
        user = User(
            user_id=user_id,
            email=email,
            name=name,
            provider='microsoft'
        )

        # Store user
        users_db[user_id] = user

        # Login user
        login_user(user)

        return redirect('/')

    except Exception as e:
        return f"Error de autenticación: {str(e)}", 400


@auth_bp.route('/auth/google')
def google_login():
    """Start Google OAuth flow"""
    if not os.getenv('GOOGLE_CLIENT_ID'):
        return jsonify({'error': 'Google auth not configured'}), 400

    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get('userinfo')

        if not userinfo:
            userinfo = oauth.google.parse_id_token(token, None)

        user_id = userinfo.get('sub')
        email = userinfo.get('email')
        name = userinfo.get('name')
        avatar = userinfo.get('picture')

        # Create user
        user = User(
            user_id=user_id,
            email=email,
            name=name,
            provider='google',
            avatar=avatar
        )

        # Store user
        users_db[user_id] = user

        # Login user
        login_user(user)

        return redirect('/')

    except Exception as e:
        return f"Error de autenticación: {str(e)}", 400


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    return redirect('/login')


@auth_bp.route('/api/auth/user')
def get_current_user():
    """Get current user info"""
    if current_user.is_authenticated:
        return jsonify(current_user.to_dict())
    return jsonify({'authenticated': False})


@auth_bp.route('/api/auth/status')
def auth_status():
    """Get auth configuration status"""
    return jsonify({
        'enabled': is_auth_enabled(),
        'providers': get_configured_providers(),
        'authenticated': current_user.is_authenticated,
        'user': current_user.to_dict() if current_user.is_authenticated else None
    })
