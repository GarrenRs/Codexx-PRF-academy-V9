import os
import json
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from datetime import datetime, timedelta
from functools import wraps
import io
import requests
import threading
import time
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import shutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET",
                                "CHANGE-THIS-SECRET-KEY-IN-PRODUCTION")

def get_current_theme():
    """Helper to get current user's theme for dashboard"""
    username = session.get('username')
    if not username:
        return 'luxury-gold'
    user_data = load_data(username=username)
    return user_data.get('settings', {}).get('theme', 'luxury-gold')

@app.context_processor
def inject_global_vars():
    """Consolidated professional context processor for all templates"""
    username = session.get('username')
    current_theme = get_current_theme()
    is_demo_mode = session.get('is_demo_mode', True)
    is_admin = session.get('is_admin', False)
    
    return {
        'current_theme': current_theme,
        'is_demo_mode': is_demo_mode,
        'is_admin': is_admin,
        'username': username,
        'current_year': datetime.now().year,
        'get_unread_messages_count': get_unread_messages_count,
        'get_visitor_count': get_visitor_count,
        'get_clients_stats': lambda: get_clients_stats(username)
    }

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'static/assets/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['JSON_AS_ASCII'] = False
app.config['SESSION_COOKIE_SECURE'] = True  # Use HTTPS in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Security Configuration - Load from environment variables
ADMIN_CREDENTIALS = {
    'username': os.environ.get('ADMIN_USERNAME', 'admin'),
    'password_hash': generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'Codexx@123456'))
}

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('backups', exist_ok=True)

# Initialize APScheduler for automatic backups
scheduler = BackgroundScheduler()
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# Advanced Security System
# Rate Limiting: Track requests per IP
RATE_LIMIT_REQUESTS = {}  # {ip: [(timestamp, endpoint), ...]}
RATE_LIMIT_MAX_REQUESTS = 10  # Max 10 requests
RATE_LIMIT_WINDOW = 60  # Per 60 seconds

# IP Logging for security tracking
IP_LOG_FILE = 'security/ip_log.json'
os.makedirs('security', exist_ok=True)

def get_client_ip():
    """Get real client IP address"""
    return request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))

def check_rate_limit(endpoint='contact'):
    """Check if IP is within rate limit"""
    client_ip = get_client_ip()
    current_time = time.time()
    
    if client_ip not in RATE_LIMIT_REQUESTS:
        RATE_LIMIT_REQUESTS[client_ip] = []
    
    # Clean old requests outside the window
    RATE_LIMIT_REQUESTS[client_ip] = [
        (ts, ep) for ts, ep in RATE_LIMIT_REQUESTS[client_ip]
        if current_time - ts < RATE_LIMIT_WINDOW
    ]
    
    # Check if limit exceeded
    endpoint_requests = [ep for ts, ep in RATE_LIMIT_REQUESTS[client_ip] if ep == endpoint]
    if len(endpoint_requests) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    # Add current request
    RATE_LIMIT_REQUESTS[client_ip].append((current_time, endpoint))
    return True

def log_ip_activity(activity_type, details=''):
    """Log IP activity for security tracking"""
    try:
        client_ip = get_client_ip()
        log_data = {
            'ip': client_ip,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'activity': activity_type,
            'details': details,
            'user_agent': request.headers.get('User-Agent', 'Unknown')[:100]
        }
        
        # Load existing logs
        try:
            with open(IP_LOG_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []
        
        logs.append(log_data)
        
        # Keep only last 1000 logs
        logs = logs[-1000:]
        
        with open(IP_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
    except Exception as e:
        app.logger.error(f"Error logging IP activity: {str(e)}")

# LIVE DEMO EDITION: Demo user credentials (restricted access for live preview)
DEMO_USER_CREDENTIALS = {
    'username': 'demo_codexx',
    'password_hash': generate_password_hash('Demo_2026!'),
    'is_demo': True
}

# Telegram Bot Configuration helper functions
def load_telegram_config():
    """Load Telegram configuration from file"""
    try:
        if os.path.exists('telegram_config.json'):
            with open('telegram_config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config.get('bot_token', ''), config.get('chat_id', '')
    except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
        app.logger.debug(f"Could not load Telegram config from file: {str(e)}")
    # Fallback to environment variables
    return os.environ.get('TELEGRAM_BOT_TOKEN', ''), os.environ.get('TELEGRAM_CHAT_ID', '')

def get_telegram_credentials(username=None):
    """Get Telegram credentials - user-specific or global fallback"""
    if username:
        # Get user-specific credentials from their data
        try:
            user_data = load_data(username=username)
            if 'notifications' in user_data and 'telegram' in user_data['notifications']:
                telegram_cfg = user_data['notifications']['telegram']
                bot_token = telegram_cfg.get('bot_token', '')
                chat_id = telegram_cfg.get('chat_id', '')
                if bot_token and chat_id:
                    return bot_token, chat_id
        except:
            pass
    
    # Fall back to global config
    bot_token, chat_id = load_telegram_config()
    return bot_token, chat_id

# Telegram Bot Configuration - loaded at startup
TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID = get_telegram_credentials()
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


# SMTP Email Configuration helper functions
def load_smtp_config(username=None):
    """Load SMTP configuration - user-specific or global"""
    # Try to load user-specific config first
    if username:
        try:
            user_data = load_data(username=username)
            if 'notifications' in user_data and 'smtp' in user_data['notifications']:
                smtp_cfg = user_data['notifications']['smtp']
                if all([smtp_cfg.get('host'), smtp_cfg.get('email'), smtp_cfg.get('password')]):
                    return smtp_cfg
        except:
            pass
    
    # Fall back to global SMTP config
    try:
        if os.path.exists('smtp_config.json'):
            with open('smtp_config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config
    except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
        app.logger.debug(f"Could not load SMTP config: {str(e)}")
    return {}


def save_smtp_config(config):
    """Save SMTP configuration to file"""
    try:
        with open('smtp_config.json', 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        app.logger.error(f"Error saving SMTP config: {str(e)}")
        return False


def send_email(recipient, subject, body, html=False, username=None):
    """Send email using SMTP - user-specific or global config"""
    try:
        smtp_config = load_smtp_config(username=username)
        if not all([smtp_config.get('host'), smtp_config.get('port'), 
                    smtp_config.get('email'), smtp_config.get('password')]):
            return False
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = smtp_config.get('email')
        msg['To'] = recipient
        
        if html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(smtp_config.get('host'), int(smtp_config.get('port'))) as server:
            server.starttls()
            server.login(smtp_config.get('email'), smtp_config.get('password'))
            server.send_message(msg)
        
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        return False


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit(
        '.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def load_data(username=None):
    """Load portfolio data for a specific user or global data"""
    try:
        data = {}
        if os.path.exists('data.json'):
            with open('data.json', 'r', encoding='utf-8') as file:
                data = json.load(file)
        
        # If a username is provided, isolate their portfolio data
        if username:
            portfolios = data.get('portfolios', {})
            if username in portfolios:
                return portfolios[username]
            else:
                # Return default template for user if not exists
                return {
                    'name': username,
                    'title': 'Web Developer & Designer',
                    'description': 'Welcome to my professional portfolio.',
                    'skills': [],
                    'projects': [],
                    'messages': [],
                    'clients': [],
                    'settings': {'theme': 'luxury-gold'},
                    'visitors': {'total': 0, 'today': [], 'unique_ips': []}
                }
        return data
    except Exception as e:
        app.logger.error(f"Error loading data: {str(e)}")
        return {}

def save_data(user_data, username=None):
    """Save portfolio data with multi-tenant isolation"""
    try:
        # Always load the full database first
        all_data = {}
        if os.path.exists('data.json'):
            with open('data.json', 'r', encoding='utf-8') as file:
                all_data = json.load(file)
        
        if username:
            # Isolate this user's data under their username key
            if 'portfolios' not in all_data:
                all_data['portfolios'] = {}
            all_data['portfolios'][username] = user_data
        else:
            # If no username, we are saving global data (users list, etc)
            all_data.update(user_data)

        with open('data.json', 'w', encoding='utf-8') as file:
            json.dump(all_data, file, ensure_ascii=False, indent=2)
    except Exception as e:
        app.logger.error(f"Error saving data: {str(e)}")

@app.route('/portfolio/<username>')
def user_portfolio(username):
    """Public view of a specific user's portfolio with theme isolation"""
    user_data = load_data(username=username)
    # Check if user exists in main data
    all_data = load_data()
    users = all_data.get('users', [])
    if not any(u['username'] == username for u in users) and username != 'admin':
        return render_template('404.html'), 404
    
    track_visitor(username=username)
    # Theme isolation: read theme from user settings, fallback to default
    current_theme = user_data.get('settings', {}).get('theme', 'luxury-gold')
    return render_template('index.html', data=user_data, is_public=True, current_theme=current_theme)


def create_backup(manual=True):
    """Create a backup of data.json to backups folder"""
    try:
        if not os.path.exists('data.json'):
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f'backup_{timestamp}.json'
        backup_path = os.path.join('backups', backup_filename)
        
        with open('data.json', 'r', encoding='utf-8') as original:
            backup_content = original.read()
            with open(backup_path, 'w', encoding='utf-8') as backup:
                backup.write(backup_content)
        
        file_size = os.path.getsize(backup_path) / 1024
        
        backup_info = {
            'filename': backup_filename,
            'timestamp': datetime.now().isoformat(),
            'size_kb': round(file_size, 2),
            'type': 'manual' if manual else 'automatic'
        }
        
        save_backup_metadata(backup_info)
        
        keep_recent_backups(max_backups=20)
        
        return backup_info
    except Exception as e:
        app.logger.error(f"Error creating backup: {str(e)}")
        return None


def save_backup_metadata(backup_info):
    """Save backup metadata to JSON file"""
    try:
        metadata_file = 'backups/backups.json'
        backups_list = []
        
        if os.path.exists(metadata_file):
            with open(metadata_file, 'r', encoding='utf-8') as f:
                backups_list = json.load(f)
        
        backups_list.append(backup_info)
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(backups_list, f, ensure_ascii=False, indent=2)
    except Exception as e:
        app.logger.error(f"Error saving backup metadata: {str(e)}")


def get_backups_list():
    """Get list of all backups with metadata"""
    try:
        metadata_file = 'backups/backups.json'
        if os.path.exists(metadata_file):
            with open(metadata_file, 'r', encoding='utf-8') as f:
                backups = json.load(f)
                return sorted(backups, key=lambda x: x['timestamp'], reverse=True)
        return []
    except Exception as e:
        app.logger.error(f"Error reading backups list: {str(e)}")
        return []


def keep_recent_backups(max_backups=20):
    """Keep only the most recent backups"""
    try:
        backups = get_backups_list()
        if len(backups) > max_backups:
            to_delete = backups[max_backups:]
            for backup in to_delete:
                backup_path = os.path.join('backups', backup['filename'])
                if os.path.exists(backup_path):
                    os.remove(backup_path)
            
            updated_backups = backups[:max_backups]
            with open('backups/backups.json', 'w', encoding='utf-8') as f:
                json.dump(updated_backups, f, ensure_ascii=False, indent=2)
    except Exception as e:
        app.logger.error(f"Error cleaning old backups: {str(e)}")


def scheduled_backup():
    """Scheduled backup job"""
    try:
        with app.app_context():
            create_backup(manual=False)
            app.logger.info("Scheduled backup created successfully")
    except Exception as e:
        app.logger.error(f"Scheduled backup failed: {str(e)}")


def reset_demo_data():
    """Reset demo data to default state for Live Demo Edition"""
    try:
        with app.app_context():
            default_demo_data = {
                'name': 'Demo Portfolio - Codexx',
                'title': 'Web Developer & Designer',
                'description': 'Experience the power of Codexx Portfolio Platform with this interactive demo',
                'photo': 'static/assets/profile-placeholder.svg',
                'about': 'Welcome to the Codexx Portfolio Platform! This is a live demo showcasing all the features available in our professional portfolio management system. Feel free to explore and customize this demo to see how your portfolio would look.',
                'skills': [
                    {'name': 'Web Development', 'level': 90},
                    {'name': 'UI/UX Design', 'level': 85},
                    {'name': 'JavaScript', 'level': 88},
                    {'name': 'React.js', 'level': 85},
                    {'name': 'Python', 'level': 80}
                ],
                'projects': load_data().get('projects', []),
                'contact': {'email': 'demo@codexx.com', 'phone': '+1 234 567 8900', 'location': 'San Francisco, CA'},
                'social': {},
                'messages': [],
                'visitors': {'total': 0, 'today': [], 'unique_ips': []},
                'settings': {'theme': 'luxury-gold'},
                'clients': []
            }
            with open('data.json', 'w', encoding='utf-8') as f:
                json.dump(default_demo_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        app.logger.error(f"Demo data reset failed: {str(e)}")


scheduler.add_job(
    scheduled_backup,
    'cron',
    hour='*',
    minute=0,
    id='daily_backup',
    name='Hourly backup',
    replace_existing=True
)

scheduler.add_job(
    reset_demo_data,
    'cron',
    hour='*',
    minute=0,
    id='demo_reset',
    name='Demo data hourly reset',
    replace_existing=True
)


def login_required(f):
    """Decorator to require login"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('dashboard_login'))
        return f(*args, **kwargs)

    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function

def disable_in_demo(f):
    """Decorator to disable actions in demo mode with specific endpoint rules"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Refresh session data from data.json if user is logged in
        if 'admin_logged_in' in session and session.get('user_id'):
            try:
                data = load_data()
                users = data.get('users', [])
                for user in users:
                    if user.get('id') == session.get('user_id'):
                        # Update session with latest status from database (data.json)
                        session['is_demo_mode'] = user.get('is_demo', True)
                        session['is_admin'] = (user.get('role') == 'admin')
                        break
            except Exception as e:
                app.logger.error(f"Error refreshing session: {str(e)}")

        if session.get('is_demo_mode'):
            # FULL CONTROL endpoints (Allowed for both GET and POST)
            allowed_endpoints = [
                'dashboard', 'dashboard_general', 'dashboard_about', 
                'dashboard_skills', 'dashboard_projects', 'dashboard_add_project', 
                'dashboard_edit_project', 'dashboard_delete_project',
                'dashboard_contact', 'dashboard_messages', 'dashboard_view_message',
                'dashboard_mark_read', 'dashboard_delete_message', 'dashboard_change_password',
                'dashboard_users' # Allow viewing users in demo mode, but POST is blocked by logic
            ]
            
            # BLOCKED endpoints (Blocked even for GET if they are sensitive)
            # Or restricted to GET only for others
            restricted_endpoints = [
                'dashboard_social', 'dashboard_clients', 'dashboard_add_client', 
                'dashboard_edit_client', 'dashboard_view_client', 'dashboard_delete_client',
                'dashboard_settings', 'dashboard_smtp', 'dashboard_telegram',
                'view_backups', 'create_manual_backup', 'download_backup', 'delete_backup',
                'export_data', 'toggle_user_demo'
            ]
            
            current_endpoint = request.endpoint
            
            if current_endpoint in restricted_endpoints and request.method == 'POST':
                flash('⚠️ Pro feature: This action requires a professional plan.', 'warning')
                return redirect(request.referrer or url_for('dashboard'))
            
            # Extra security: prevent users from reaching sensitive admin settings even on GET
            sensitive_get_endpoints = ['dashboard_smtp', 'dashboard_telegram', 'view_backups']
            if current_endpoint in sensitive_get_endpoints:
                flash('⚠️ Pro feature: Access restricted in demo mode.', 'warning')
                return redirect(url_for('dashboard'))
                
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration from landing page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not username or not password or not email:
            flash('All fields are required', 'error')
            return redirect(url_for('register'))

        data = load_data()
        if 'users' not in data:
            data['users'] = []

        if any(u['username'] == username for u in data['users']):
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        new_user = {
            'id': len(data['users']) + 1,
            'username': username,
            'password_hash': generate_password_hash(password),
            'email': email,
            'role': 'user',
            'is_demo': False,  # New users get full access (was True before, now changed)
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        data['users'].append(new_user)
        
        # Initialize default portfolio for the new user
        if 'portfolios' not in data:
            data['portfolios'] = {}
            
        data['portfolios'][username] = {
            'name': username,
            'title': 'Web Developer & Designer',
            'description': 'Welcome to my professional portfolio.',
            'skills': [],
            'projects': [],
            'settings': {'theme': 'luxury-gold'} # Default theme
        }
        
        save_data(data)
        flash('Registration successful! Your account is active and ready to use. Please login.', 'success')
        return redirect(url_for('dashboard_login'))

    return render_template('register.html')


@app.route('/dashboard/users')
@login_required
@admin_required
@disable_in_demo
def dashboard_users():
    """Manage users and permissions (Admin only)"""
    data = load_data()
    users = data.get('users', [])
    return render_template('dashboard/users.html', users=users)


def send_telegram_notification(message_text, username=None):
    """Send notification to Telegram - user-specific"""
    # Get credentials for specific user or global
    bot_token, chat_id = get_telegram_credentials(username=username)
    if not bot_token or not chat_id:
        return False
    
    try:
        # Check if message_text is already formatted (for contact forms) or needs formatting (for client updates)
        if isinstance(message_text, dict):
            # Old contact form format
            name = message_text.get('name', '')
            email = message_text.get('email', '')
            body = message_text.get('message', '')
            telegram_message = f"""
🔔 <b>New Contact Message</b>

📝 <b>Name:</b> {name}
📧 <b>Email:</b> {email}

💬 <b>Message:</b>
{body}

⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        else:
            # New format (already formatted string for client updates)
            telegram_message = message_text
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': telegram_message,
            'parse_mode': 'HTML'
        }
        
        # Send in background thread to not block the request
        response = requests.post(url, json=payload, timeout=5)
        return response.status_code == 200
    except Exception as e:
        app.logger.error(f"Error sending Telegram notification: {str(e)}")
        return False


def send_telegram_event_notification(event_type, details=None, username=None):
    """Send event-based notifications - per-user"""
    bot_token, chat_id = get_telegram_credentials(username=username)
    if not bot_token or not chat_id:
        return False
    
    try:
        event_messages = {
            'new_message': f"""📨 <b>New Contact Message</b>
{details}
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}""",
            
            'new_project': f"""🚀 <b>New Project Added</b>
📌 {details}
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}""",
            
            'project_updated': f"""✏️ <b>Project Updated</b>
📌 {details}
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}""",
            
            'login_attempt': f"""🔐 <b>Dashboard Login</b>
👤 User: {details}
⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        }
        
        message_text = event_messages.get(event_type, f"{event_type}: {details}")
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message_text,
            'parse_mode': 'HTML'
        }
        
        response = requests.post(url, json=payload, timeout=5)
        return response.status_code == 200
    except Exception as e:
        app.logger.error(f"Error sending event notification: {str(e)}")
        return False


def send_event_notification_async(event_type, details=None, username=None):
    """Send event notification asynchronously - per-user"""
    thread = threading.Thread(target=send_telegram_event_notification, args=(event_type, details, username))
    thread.daemon = True
    thread.start()


def send_telegram_notification_async(message_text, username=None):
    """Send Telegram notification asynchronously"""
    bot_token, chat_id = get_telegram_credentials(username=username)
    if bot_token and chat_id:
        thread = threading.Thread(target=send_telegram_notification, args=(message_text, username))
        thread.daemon = True
        thread.start()


def save_message(name, email, message, username=None, priority='normal'):
    """Save contact message per user and send notifications with priority"""
    if username is None:
        # Try to get from session, otherwise default to admin
        username = session.get('username')
        if not username:
            # For public contact forms without identified user, route to admin
            username = ADMIN_CREDENTIALS['username']
    
    data = load_data(username=username)
    if 'messages' not in data:
        data['messages'] = []

    message_ids = [m.get('id', 0) for m in data.get('messages', [])]
    new_id = max(message_ids) + 1 if message_ids else 1

    client_ip = get_client_ip()
    new_message = {
        'id': new_id,
        'name': name,
        'email': email,
        'message': message,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'read': False,
        'ip': client_ip,
        'recipient': username,  # Store which user received this message
        'priority': priority,  # Add priority field (high, normal, low)
        'category': 'general'  # Default category for future filtering
    }

    data['messages'].append(new_message)
    save_data(data, username=username)
    
    # Log the activity
    log_ip_activity('contact_message', f"From: {email} to {username}")
    
    # Send Telegram notification to the recipient user (using their config)
    notification_msg = f"""
📨 <b>New Contact Message</b>

📝 <b>Name:</b> {name}
📧 <b>Email:</b> {email}

💬 <b>Message:</b>
{message}

⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    send_telegram_notification_async(notification_msg, username=username)
    
    # Send email notification to the recipient user (using their config)
    smtp_config = load_smtp_config(username=username)
    if smtp_config.get('email'):
        email_subject = f'📬 New Contact Message from {name}'
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #D4AF37;">📬 New Contact Message</h2>
                <p><strong>Name:</strong> {name}</p>
                <p><strong>Email:</strong> <a href="mailto:{email}">{email}</a></p>
                <p><strong>Message:</strong></p>
                <p style="background: #f5f5f5; padding: 10px; border-left: 4px solid #D4AF37;">
                    {message.replace(chr(10), '<br>')}
                </p>
                <p style="margin-top: 20px; color: #666; font-size: 12px;">
                    Received at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </body>
        </html>
        """
        send_email(smtp_config.get('email'), email_subject, email_body, html=True, username=username)
    
    return new_id


def get_unread_messages_count():
    """Get count of unread messages"""
    data = load_data()
    return len(
        [m for m in data.get('messages', []) if not m.get('read', False)])


def track_visitor(username=None):
    """Track visitor with per-user isolation"""
    if username is None:
        username = session.get('username', 'public')
    
    # Track per user (load and save user-specific visitor data)
    data = load_data(username=username)
    if 'visitors' not in data:
        data['visitors'] = {'total': 0, 'today': [], 'unique_ips': []}

    visitor_ip = request.environ.get(
        'HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    today = datetime.now().strftime('%Y-%m-%d')

    # Only count unique IPs per day
    today_ips = [v.get('ip') for v in data['visitors'].get('today', []) if v.get('date') == today]
    if visitor_ip not in today_ips:
        data['visitors']['total'] = data['visitors'].get('total', 0) + 1

    # Keep today's visitors only
    data['visitors']['today'] = [
        v for v in data['visitors'].get('today', []) if v.get('date') == today
    ]
    data['visitors']['today'].append({
        'ip': visitor_ip,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'date': today
    })

    # Track unique IPs
    if isinstance(data['visitors'].get('unique_ips'), list):
        unique_ips_set = set(data['visitors']['unique_ips'])
    else:
        unique_ips_set = set()
    unique_ips_set.add(visitor_ip)
    data['visitors']['unique_ips'] = list(unique_ips_set)

    save_data(data, username=username)
    
    return data['visitors']['total']


def get_visitor_count():
    """Get total visitor count"""
    data = load_data()
    return data.get('visitors', {}).get('total', 0)


def mark_message_as_read(message_id):
    """Mark message as read"""
    data = load_data()
    for message in data.get('messages', []):
        if message.get('id') == message_id:
            message['read'] = True
            break
    save_data(data)


def get_clients_stats(username=None):
    """Get clients statistics for a specific user"""
    data = load_data(username=username)
    clients = data.get('clients', [])

    total_clients = len(clients)
    active_clients = len([c for c in clients if c.get('status') == 'active'])
    completed_clients = len(
        [c for c in clients if c.get('status') == 'completed'])
    pending_clients = len([c for c in clients if c.get('status') == 'pending'])

    total_revenue = sum(
        float(c.get('price', 0)) for c in clients if c.get('price'))

    return {
        'total': total_clients,
        'active': active_clients,
        'completed': completed_clients,
        'pending': pending_clients,
        'revenue': total_revenue
    }


# Error handlers
@app.errorhandler(400)
def bad_request(e):
    """Custom 400 error page"""
    return render_template('400.html'), 400


@app.errorhandler(403)
def forbidden(e):
    """Custom 403 error page"""
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page"""
    app.logger.error(f"Server Error: {str(e)}")
    return render_template('500.html'), 500


@app.errorhandler(503)
def service_unavailable(e):
    """Custom 503 error page"""
    return render_template('503.html'), 503


@app.errorhandler(413)
def file_too_large(e):
    """File upload too large"""
    flash('File is too large. Maximum size is 16MB.', 'error')
    return redirect(request.url)


# Public routes
@app.route('/landing')
def landing():
    """Landing/Marketing page for the platform"""
    data = load_data(username=ADMIN_CREDENTIALS['username'])
    return render_template('landing.html', data=data)


@app.route('/')
def index():
    """Route for the main application"""
    if 'admin_logged_in' in session:
        # Redirect to dashboard instead of portfolio
        return redirect(url_for('dashboard'))
    # Load data for portfolio display and contact form
    data = load_data(username=ADMIN_CREDENTIALS['username'])
    return render_template('landing.html', data=data)




@app.route('/catalog')
@login_required
def catalog():
    """Feature catalog page"""
    return render_template('catalog.html')


def send_confirmation_email(name, email, portfolio_owner_email):
    """Send confirmation email to visitor"""
    try:
        subject = "Message Received - We'll Be In Touch Soon"
        html_body = f"""
        <div style="font-family: 'Poppins', sans-serif; max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 0; border-radius: 10px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.2);">
            <div style="background: white; padding: 40px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #333; margin: 0; font-size: 28px;">✓ Message Received</h2>
                </div>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6; margin: 0 0 20px 0;">
                    Hello <strong>{name}</strong>,
                </p>
                
                <p style="color: #555; font-size: 16px; line-height: 1.6; margin: 0 0 20px 0;">
                    Thank you for reaching out! We've received your message and appreciate you taking the time to contact us.
                </p>
                
                <div style="background: #f8f9fa; border-left: 4px solid #667eea; padding: 20px; margin: 25px 0; border-radius: 5px;">
                    <p style="color: #666; font-size: 14px; margin: 0;">
                        <strong>What happens next?</strong><br>
                        Our team will review your message and get back to you as soon as possible at <strong>{email}</strong>. We typically respond within 24 hours.
                    </p>
                </div>
                
                <p style="color: #666; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0;">
                    If you have any additional information to add, feel free to reply to this email directly.
                </p>
                
                <div style="text-align: center; margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">
                    <p style="color: #999; font-size: 12px; margin: 0;">
                        © 2026 Codexx. All rights reserved.
                    </p>
                </div>
            </div>
        </div>
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = portfolio_owner_email or 'noreply@codexx.com'
        msg['To'] = email
        msg.attach(MIMEText(html_body, 'html'))
        
        # Try to send via SMTP if configured, otherwise skip
        try:
            smtp_config = load_smtp_config()
            if all([smtp_config.get('host'), smtp_config.get('port'), 
                    smtp_config.get('email'), smtp_config.get('password')]):
                with smtplib.SMTP(smtp_config.get('host'), int(smtp_config.get('port'))) as server:
                    server.starttls()
                    server.login(smtp_config.get('email'), smtp_config.get('password'))
                    server.send_message(msg)
                return True
        except Exception as e:
            app.logger.debug(f"Could not send confirmation email via SMTP: {str(e)}")
        
        return False
    except Exception as e:
        app.logger.error(f"Error preparing confirmation email: {str(e)}")
        return False


@app.route('/contact', methods=['POST'])
def contact():
    """Handle contact form submission with security"""
    # Check honeypot field
    honeypot = request.form.get('website', '').strip()
    if honeypot:
        # Bot detected - silently fail
        log_ip_activity('bot_detected', 'Contact form honeypot triggered')
        flash('Thank you for your message! I will get back to you soon.', 'success')
        return redirect(url_for('index') + '#contact')
    
    # Check rate limiting
    if not check_rate_limit('contact'):
        log_ip_activity('rate_limit_exceeded', 'Contact form submissions exceeded')
        flash('Too many messages. Please wait a moment before sending another message.', 'error')
        return redirect(url_for('index') + '#contact')
    
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    message = request.form.get('message', '').strip()

    if name and email and message:
        try:
            # Determine which portfolio user this message is for
            # Check if form contains portfolio_owner field (set by template)
            portfolio_owner = request.form.get('portfolio_owner', '').strip()
            
            # If not in form, try to extract from referrer URL
            if not portfolio_owner and request.referrer:
                # Check if referrer contains /portfolio/<username>
                import re
                match = re.search(r'/portfolio/([a-zA-Z0-9_-]+)', request.referrer)
                if match:
                    portfolio_owner = match.group(1)
            
            # Default to admin if we couldn't determine portfolio owner
            if not portfolio_owner:
                portfolio_owner = ADMIN_CREDENTIALS['username']
            
            # Get portfolio owner's email for confirmation email
            owner_data = load_data(username=portfolio_owner)
            owner_email = owner_data.get('contact', {}).get('email', 'support@codexx.com')
            
            # Save message to the correct portfolio owner
            # Note: save_message() handles both Telegram and email notifications
            save_message(name, email, message, username=portfolio_owner)
            
            # Send confirmation email to visitor (async for better UX)
            thread = threading.Thread(target=send_confirmation_email, args=(name, email, owner_email))
            thread.daemon = True
            thread.start()
            
            flash('Thank you for your message! I will get back to you soon. Check your email for confirmation.',
                  'success')
        except Exception as e:
            app.logger.error(f"Contact form error: {str(e)}")
            flash(
                'Sorry, there was an error sending your message. Please try again.',
                'error')
    else:
        flash('Please fill in all required fields.', 'error')

    return redirect(url_for('index') + '#contact')


@app.route('/project/<int:project_id>')
def project_detail(project_id):
    """Project detail page"""
    data = load_data()
    project = next(
        (p for p in data.get('projects', []) if p.get('id') == project_id),
        None)

    if not project:
        return render_template('404.html'), 404

    return render_template('project_detail.html', project=project, data=data)


@app.route('/sitemap.xml')
def sitemap():
    """Generate dynamic sitemap for SEO"""
    data = load_data()
    base_url = request.url_root.rstrip('/')
    
    sitemap_entries = []
    sitemap_entries.append({
        'loc': f'{base_url}/',
        'changefreq': 'weekly',
        'priority': '1.0',
        'lastmod': datetime.now().strftime('%Y-%m-%d')
    })
    
    for project in data.get('projects', []):
        sitemap_entries.append({
            'loc': f"{base_url}/project/{project['id']}",
            'changefreq': 'monthly',
            'priority': '0.8',
            'lastmod': project.get('created_at', datetime.now().strftime('%Y-%m-%d')).split()[0]
        })
    
    sitemap_xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    sitemap_xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:news="http://www.google.com/schemas/sitemap-news/0.9">')
    
    for entry in sitemap_entries:
        sitemap_xml.append('<url>')
        sitemap_xml.append(f'<loc>{entry["loc"]}</loc>')
        sitemap_xml.append(f'<lastmod>{entry["lastmod"]}</lastmod>')
        sitemap_xml.append(f'<changefreq>{entry["changefreq"]}</changefreq>')
        sitemap_xml.append(f'<priority>{entry["priority"]}</priority>')
        sitemap_xml.append('</url>')
    
    sitemap_xml.append('</urlset>')
    
    response = app.make_response('\n'.join(sitemap_xml))
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    return response


@app.route('/robots.txt')
def robots():
    """Generate robots.txt for SEO"""
    robots_txt = """User-agent: *
Allow: /
Allow: /project/
Allow: /cv-preview
Allow: /sitemap.xml
Disallow: /dashboard/
Disallow: /static/
Disallow: /*.json$

Sitemap: """ + request.url_root.rstrip('/') + """/sitemap.xml
User-agent: GPTBot
Disallow: /

User-agent: CCBot
Disallow: /"""
    
    response = app.make_response(robots_txt)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return response


@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    return send_file('static/favicon.ico', mimetype='image/x-icon')


# Backup & Restore Routes
@app.route('/dashboard/backups')
@login_required
def view_backups():
    """View all available backups - redirect to settings"""
    return redirect(url_for('dashboard_settings') + '#backups')


@app.route('/backup/create', methods=['POST'])
@login_required
def create_manual_backup():
    """Create a manual backup"""
    try:
        backup_info = create_backup(manual=True)
        if backup_info:
            flash(f'✓ Backup created successfully: {backup_info["filename"]}', 'success')
            username = session.get('username')
            send_event_notification_async('backup_created', f'Manual backup: {backup_info["filename"]} ({backup_info["size_kb"]} KB)', username=username)
        else:
            flash('Error creating backup', 'error')
    except Exception as e:
        app.logger.error(f"Error creating manual backup: {str(e)}")
        flash('Error creating backup', 'error')
    return redirect(url_for('dashboard_settings') + '#backups')


@app.route('/backup/restore/<filename>', methods=['POST'])
@login_required
@disable_in_demo
def restore_backup(filename):
    """Restore a backup"""
    try:
        filename = secure_filename(filename)
        backup_path = os.path.join('backups', filename)
        
        if not os.path.exists(backup_path):
            flash('Backup file not found', 'error')
            return redirect(url_for('dashboard_settings') + '#backups')
        
        if os.path.exists('data.json'):
            recovery_backup = f'backups/recovery_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            shutil.copy('data.json', recovery_backup)
        
        shutil.copy(backup_path, 'data.json')
        flash(f'✓ Portfolio restored from backup: {filename}', 'success')
        username = session.get('username')
        send_event_notification_async('backup_restored', f'Restored from: {filename}', username=username)
        return redirect(url_for('dashboard_settings') + '#backups')
    except Exception as e:
        app.logger.error(f"Error restoring backup: {str(e)}")
        flash('Error restoring backup', 'error')
        return redirect(url_for('dashboard_settings') + '#backups')


@app.route('/backup/download/<filename>')
@login_required
def download_backup(filename):
    """Download a backup file"""
    try:
        filename = secure_filename(filename)
        backup_path = os.path.join('backups', filename)
        
        if not os.path.exists(backup_path):
            flash('Backup file not found', 'error')
            return redirect(url_for('dashboard_settings') + '#backups')
        
        return send_file(backup_path, as_attachment=True, download_name=filename)
    except Exception as e:
        app.logger.error(f"Error downloading backup: {str(e)}")
        flash('Error downloading backup', 'error')
        return redirect(url_for('dashboard_settings') + '#backups')


@app.route('/backup/delete/<filename>', methods=['POST'])
@login_required
@disable_in_demo
def delete_backup(filename):
    """Delete a backup file"""
    try:
        filename = secure_filename(filename)
        backup_path = os.path.join('backups', filename)
        
        if not os.path.exists(backup_path):
            flash('Backup file not found', 'error')
            return redirect(url_for('dashboard_settings') + '#backups')
        
        os.remove(backup_path)
        
        backups = get_backups_list()
        updated_backups = [b for b in backups if b['filename'] != filename]
        with open('backups/backups.json', 'w', encoding='utf-8') as f:
            json.dump(updated_backups, f, ensure_ascii=False, indent=2)
        
        flash(f'✓ Backup deleted: {filename}', 'success')
    except Exception as e:
        app.logger.error(f"Error deleting backup: {str(e)}")
        flash('Error deleting backup', 'error')
    
    return redirect(url_for('dashboard_settings') + '#backups')


@app.route('/api/backups')
@login_required
def api_backups():
    """API endpoint to get backups list"""
    try:
        backups = get_backups_list()
        return jsonify(backups)
    except Exception as e:
        app.logger.error(f"Error fetching backups: {str(e)}")
        return jsonify([]), 500


# Admin routes
@app.route('/dashboard/login', methods=['GET', 'POST'])
def dashboard_login():
    """Admin and User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = get_client_ip()

        # Check main Admin
        if username == ADMIN_CREDENTIALS['username'] and check_password_hash(
                ADMIN_CREDENTIALS['password_hash'], password):
            session['admin_logged_in'] = True
            session['is_admin'] = True
            session['is_demo_mode'] = False
            session['username'] = username
            flash('Admin Login Successful!', 'success')
            log_ip_activity('admin_login', f"User: {username}")
            send_event_notification_async('login_attempt', f"Admin: {username} (IP: {client_ip})", username=username)
            return redirect(url_for('dashboard'))

        # Check other users in data.json
        data = load_data()
        users = data.get('users', [])
        for user in users:
            if user['username'] == username and check_password_hash(
                    user['password_hash'], password):
                session['admin_logged_in'] = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = (user.get('role') == 'admin')
                # Explicitly check for admin user in users list to prevent demo mode on them
                if user['username'] == ADMIN_CREDENTIALS['username']:
                    session['is_demo_mode'] = False
                else:
                    session['is_demo_mode'] = user.get('is_demo', True)
                
                flash(f'Welcome back, {username}!', 'success')
                log_ip_activity('user_login', f"User: {username}")
                send_event_notification_async('login_attempt', f"User: {username} (IP: {client_ip})", username=username)
                return redirect(url_for('dashboard'))

        flash('Invalid credentials. Please try again.', 'error')
        log_ip_activity('failed_login', f"Username: {username}")

    return render_template('dashboard/login.html')

@app.route('/dashboard/users/toggle_demo/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@disable_in_demo
def toggle_user_demo(user_id):
    """Toggle user between Demo Mode and Full Access"""
    data = load_data()
    user_found = False
    
    if 'users' in data:
        for user in data['users']:
            if user.get('id') == user_id:
                # Toggle is_demo flag (default to True if not set)
                current_status = user.get('is_demo', True)
                user['is_demo'] = not current_status
                user_found = True
                
                # If this is the current logged in user, update their session too
                if session.get('user_id') == user_id:
                    session['is_demo_mode'] = user['is_demo']
                
                status_text = "Demo Mode" if user['is_demo'] else "Full Access"
                flash(f"User {user['username']} updated to {status_text}", 'success')
                break
    
    if user_found:
        save_data(data)
    else:
        flash("User not found", "error")
        
    return redirect(url_for('dashboard_users'))


@app.route('/dashboard/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@disable_in_demo
def delete_user(user_id):
    """Delete a user account and all their data"""
    data = load_data()
    user_found = False
    username_to_delete = None
    
    # Prevent deleting admin account
    if user_id == 1:  # Admin user typically has ID 1
        flash('⚠️ Cannot delete the admin account', 'error')
        return redirect(url_for('dashboard_users'))
    
    # Prevent self-deletion
    if session.get('user_id') == user_id:
        flash('⚠️ You cannot delete your own account', 'error')
        return redirect(url_for('dashboard_users'))
    
    if 'users' in data:
        for i, user in enumerate(data['users']):
            if user.get('id') == user_id:
                username_to_delete = user.get('username')
                user_found = True
                # Remove user from list
                data['users'].pop(i)
                break
    
    if user_found and username_to_delete:
        # Delete user's portfolio data
        if 'portfolios' in data and username_to_delete in data['portfolios']:
            del data['portfolios'][username_to_delete]
        
        save_data(data)
        flash(f'User account "{username_to_delete}" has been successfully deleted along with all their data', 'success')
    else:
        flash('User not found', 'error')
        
    return redirect(url_for('dashboard_users'))


@app.route('/dashboard/logout')
@login_required
def dashboard_logout():
    """User/Admin logout"""
    session.clear()
    flash('Logout successful', 'success')
    return redirect(url_for('dashboard_login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    username = session.get('username')
    user_data = load_data(username=username)
    stats = {
        'projects': len(user_data.get('projects', [])),
        'skills': len(user_data.get('skills', [])),
        'messages': len(user_data.get('messages', [])),
        'unread_messages': len([m for m in user_data.get('messages', []) if not m.get('read', False)]),
        'visitors': user_data.get('visitors', {}).get('total', 0),
        'today_visitors': len(user_data.get('visitors', {}).get('today', []))
    }
    return render_template('dashboard/index.html', data=user_data, stats=stats)


@app.route('/documentation')
def documentation():
    """Serve documentation page"""
    import os
    doc_path = os.path.join('Documentation', 'English', 'documentation-english.html')
    if os.path.exists(doc_path):
        return send_file(doc_path)
    else:
        return render_template('404.html'), 404


@app.route('/dashboard/settings', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_settings():
    """Dashboard settings page for current user"""
    username = session.get('username')
    data = load_data(username=username)
    
    if request.method == 'POST':
        if 'settings' not in data:
            data['settings'] = {}
        
        selected_theme = request.form.get('theme', 'luxury-gold')
        valid_themes = ['luxury-gold', 'modern-dark', 'clean-light', 'terracotta-red', 'vibrant-green', 'silver-grey']
        if selected_theme in valid_themes:
            # Theme isolation: saves specifically to the current user's profile
            data['settings']['theme'] = selected_theme
            save_data(data, username=username)
            flash(f'Theme changed to {selected_theme.replace("-", " ").title()} successfully', 'success')
        else:
            flash('Invalid theme selected', 'error')
        
        return redirect(url_for('dashboard_settings'))
    
    themes = [
        {'id': 'luxury-gold', 'name': 'Luxury Gold', 'icon': 'fas fa-crown', 'description': 'Premium & Classic'},
        {'id': 'modern-dark', 'name': 'Modern Dark', 'icon': 'fas fa-zap', 'description': 'Tech & Trendy'},
        {'id': 'clean-light', 'name': 'Clean Light', 'icon': 'fas fa-sun', 'description': 'Minimal & Fresh'},
        {'id': 'terracotta-red', 'name': 'Terracotta Red', 'icon': 'fas fa-fire', 'description': 'Warm & Modern'},
        {'id': 'vibrant-green', 'name': 'Vibrant Green', 'icon': 'fas fa-leaf', 'description': 'Natural & Fresh'},
        {'id': 'silver-grey', 'name': 'Silver Grey', 'icon': 'fas fa-gem', 'description': 'Sophisticated & Modern'}
    ]
    
    current_theme = data.get('settings', {}).get('theme', 'luxury-gold')
    
    # Load Telegram credentials (user-specific)
    telegram_bot_token, telegram_chat_id = get_telegram_credentials(username=username)
    telegram_status = bool(telegram_bot_token and telegram_chat_id)
    
    telegram_bot_token_display = telegram_bot_token[:10] + '...' if telegram_bot_token else ''
    
    # Load SMTP config (user-specific)
    smtp_config = load_smtp_config(username=username)
    smtp_host = smtp_config.get('host', '')
    smtp_port = smtp_config.get('port', '')
    smtp_email = smtp_config.get('email', '')
    smtp_status = bool(all([smtp_host, smtp_port, smtp_email, smtp_config.get('password')]))
    
    return render_template('dashboard/settings.html', themes=themes, current_theme=current_theme, data=data,
                         telegram_bot_token=telegram_bot_token_display,
                         telegram_chat_id=telegram_chat_id,
                         telegram_status=telegram_status,
                         smtp_host=smtp_host,
                         smtp_port=smtp_port,
                         smtp_email=smtp_email,
                         smtp_status=smtp_status)


@app.route('/dashboard/telegram', methods=['POST'])
@login_required
@disable_in_demo
def dashboard_telegram():
    """Update Telegram settings - per-user configuration"""
    username = session.get('username')
    bot_token = request.form.get('bot_token', '').strip()
    chat_id = request.form.get('chat_id', '').strip()
    
    if not bot_token or not chat_id:
        flash('Please provide both Bot Token and Chat ID', 'error')
        return redirect(url_for('dashboard_settings'))
    
    try:
        # Test connection to Telegram API
        test_url = f"https://api.telegram.org/bot{bot_token}/getMe"
        response = requests.get(test_url, timeout=5)
        
        if response.status_code != 200:
            flash('Invalid Telegram Bot Token. Please check and try again.', 'error')
            return redirect(url_for('dashboard_settings'))
        
        # Send test message
        test_message_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        test_payload = {
            'chat_id': chat_id,
            'text': '✅ Telegram notifications configured successfully for your Codexx Portfolio!',
            'parse_mode': 'HTML'
        }
        test_response = requests.post(test_message_url, json=test_payload, timeout=5)
        
        if test_response.status_code != 200:
            flash('Invalid Telegram Chat ID or permission denied. Please check and try again.', 'error')
            return redirect(url_for('dashboard_settings'))
        
        # Save to user data (per-user configuration)
        data = load_data(username=username)
        if 'notifications' not in data:
            data['notifications'] = {}
        
        data['notifications']['telegram'] = {
            'bot_token': bot_token,
            'chat_id': chat_id,
            'configured_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        save_data(data, username=username)
        
        flash('✅ Telegram notifications configured successfully for your portfolio! Check your Telegram for a test message.', 'success')
        
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Telegram configuration error: {str(e)}")
        flash('Connection error. Please check your internet connection and try again.', 'error')
    except Exception as e:
        app.logger.error(f"Telegram error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
    
    return redirect(url_for('dashboard_settings'))


@app.route('/dashboard/smtp', methods=['POST'])
@login_required
@disable_in_demo
def dashboard_smtp():
    """Update SMTP settings - per-user configuration"""
    username = session.get('username')
    smtp_host = request.form.get('smtp_host', '').strip()
    smtp_port = request.form.get('smtp_port', '').strip()
    smtp_email = request.form.get('smtp_email', '').strip()
    smtp_password = request.form.get('smtp_password', '').strip()
    
    if not all([smtp_host, smtp_port, smtp_email, smtp_password]):
        flash('Please provide all SMTP settings', 'error')
        return redirect(url_for('dashboard_settings'))
    
    try:
        # Save to user data (per-user configuration)
        data = load_data(username=username)
        if 'notifications' not in data:
            data['notifications'] = {}
        
        data['notifications']['smtp'] = {
            'host': smtp_host,
            'port': smtp_port,
            'email': smtp_email,
            'password': smtp_password,
            'configured_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        save_data(data, username=username)
        
        flash('✅ SMTP settings saved successfully for your portfolio!', 'success')
    except Exception as e:
        app.logger.error(f"SMTP configuration error: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
    
    return redirect(url_for('dashboard_settings'))


@app.route('/dashboard/email-test', methods=['POST'])
@login_required
@disable_in_demo
def email_test_connection():
    """Test SMTP connection"""
    username = session.get('username')
    smtp_config = load_smtp_config(username=username)
    
    if not all([smtp_config.get('host'), smtp_config.get('email'), smtp_config.get('password')]):
        return jsonify({'success': False, 'error': 'SMTP not configured'})
    
    try:
        test_subject = '🧪 Codexx Portfolio - Email Test'
        test_body = """
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2 style="color: #D4AF37;">✅ Email Connection Test Successful!</h2>
                <p>Your SMTP configuration is working perfectly.</p>
                <p><strong>Email Address:</strong> {}</p>
                <p><strong>Server:</strong> {}:{}</p>
                <p style="margin-top: 20px; color: #666; font-size: 12px;">
                    This is a test email from your Codexx Portfolio.
                </p>
            </body>
        </html>
        """.format(smtp_config.get('email'), smtp_config.get('host'), smtp_config.get('port'))
        
        if send_email(smtp_config.get('email'), test_subject, test_body, html=True, username=username):
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to send email'})
    except Exception as e:
        app.logger.error(f"Email test error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/dashboard/telegram-test', methods=['POST'])
@login_required
@disable_in_demo
def telegram_test_connection():
    """Test Telegram connection"""
    username = session.get('username')
    bot_token, chat_id = get_telegram_credentials(username=username)
    
    if not bot_token or not chat_id:
        return jsonify({'success': False, 'error': 'Telegram not configured'})
    
    try:
        # Send test message
        test_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        test_payload = {
            'chat_id': chat_id,
            'text': '🧪 <b>Connection Test Successful!</b>\n✅ Your Portfolio Bot is working perfectly!',
            'parse_mode': 'HTML'
        }
        test_response = requests.post(test_url, json=test_payload, timeout=5)
        
        if test_response.status_code == 200:
            return jsonify({'success': True, 'message': 'Test message sent successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to send test message'})
    except Exception as e:
        app.logger.error(f"Test connection error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@app.route('/dashboard/general', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_general():
    """Edit general information"""
    username = session.get('username')
    data = load_data(username=username)

    if request.method == 'POST':
        data['name'] = request.form.get('name', '')
        data['title'] = request.form.get('title', '')
        data['description'] = request.form.get('description', '')

        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"profile_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                data['photo'] = f"static/assets/uploads/{filename}"

        save_data(data, username=username)
        flash('General information saved successfully', 'success')
        return redirect(url_for('dashboard_general'))

    return render_template('dashboard/general.html', data=data)


@app.route('/dashboard/about', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_about():
    """Edit about section"""
    username = session.get('username')
    data = load_data(username=username)

    if request.method == 'POST':
        data['about'] = request.form.get('about', '')
        save_data(data, username=username)
        flash('About section saved successfully', 'success')
        return redirect(url_for('dashboard_about'))

    return render_template('dashboard/about.html', data=data)


@app.route('/dashboard/skills', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_skills():
    """Edit skills section"""
    username = session.get('username')
    data = load_data(username=username)

    if request.method == 'POST':
        skills = []
        skill_names = request.form.getlist('skill_name[]')
        skill_levels = request.form.getlist('skill_level[]')

        for name, level in zip(skill_names, skill_levels):
            if name.strip():
                skills.append({
                    'name':
                    name.strip(),
                    'level':
                    int(level)
                    if level.isdigit() and 0 <= int(level) <= 100 else 0
                })

        data['skills'] = skills
        save_data(data, username=username)
        flash('Skills saved successfully', 'success')
        return redirect(url_for('dashboard_skills'))

    return render_template('dashboard/skills.html', data=data)


@app.route('/dashboard/projects')
@login_required
@disable_in_demo
def dashboard_projects():
    """List all projects"""
    username = session.get('username')
    data = load_data(username=username)
    return render_template('dashboard/projects.html', data=data)


@app.route('/dashboard/projects/add', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_add_project():
    """Add new project"""
    username = session.get('username')
    if request.method == 'POST':
        data = load_data(username=username)

        project_ids = [p.get('id', 0) for p in data.get('projects', [])]
        new_id = max(project_ids) + 1 if project_ids else 1

        image_path = "static/assets/project-placeholder.svg"
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"project_{username}_{new_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = f"static/assets/uploads/{filename}"

        technologies = [
            tech.strip() for tech in request.form.getlist('technologies[]')
            if tech.strip()
        ]
        short_desc = request.form.get('short_description', '').strip()
        full_content = request.form.get('content', '').strip()

        new_project = {
            'id': new_id,
            'title': request.form.get('title', '').strip(),
            'short_description': short_desc,
            'content': full_content,
            'description': short_desc,
            'image': image_path,
            'demo_url': request.form.get('demo_url', '').strip() or '#',
            'github_url': request.form.get('github_url', '').strip() or '#',
            'technologies': technologies
        }

        if 'projects' not in data:
            data['projects'] = []
        data['projects'].append(new_project)

        save_data(data, username=username)
        flash('Project added successfully', 'success')
        return redirect(url_for('dashboard_projects'))

    return render_template('dashboard/add_project.html')


@app.route('/dashboard/projects/edit/<int:project_id>',
           methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_edit_project(project_id):
    """Edit existing project for current user"""
    username = session.get('username')
    data = load_data(username=username)
    project = next(
        (p for p in data.get('projects', []) if p.get('id') == project_id),
        None)

    if not project:
        flash('Project not found', 'error')
        return redirect(url_for('dashboard_projects'))

    if request.method == 'POST':
        short_desc = request.form.get('short_description', '').strip()
        full_content = request.form.get('content', '').strip()

        project['title'] = request.form.get('title', '').strip()
        project['short_description'] = short_desc
        project['content'] = full_content
        project['description'] = short_desc
        project['demo_url'] = request.form.get('demo_url', '').strip() or '#'
        project['github_url'] = request.form.get('github_url',
                                                 '').strip() or '#'

        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"project_{username}_{project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                project['image'] = f"static/assets/uploads/{filename}"

        project['technologies'] = [
            tech.strip() for tech in request.form.getlist('technologies[]')
            if tech.strip()
        ]

        save_data(data, username=username)
        flash('Project updated successfully', 'success')
        return redirect(url_for('dashboard_projects'))

    return render_template('dashboard/edit_project.html', project=project)


@app.route('/dashboard/projects/delete/<int:project_id>', methods=['POST'])
@login_required
@disable_in_demo
def dashboard_delete_project(project_id):
    """Delete project for current user"""
    username = session.get('username')
    data = load_data(username=username)
    data['projects'] = [
        p for p in data.get('projects', []) if p.get('id') != project_id
    ]
    save_data(data, username=username)
    flash('Project deleted successfully', 'success')
    return redirect(url_for('dashboard_projects'))


@app.route('/dashboard/contact', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_contact():
    """Edit contact information for current user"""
    username = session.get('username')
    data = load_data(username=username)

    if request.method == 'POST':
        if 'contact' not in data:
            data['contact'] = {}

        data['contact']['email'] = request.form.get('email', '')
        data['contact']['phone'] = request.form.get('phone', '')
        data['contact']['location'] = request.form.get('location', '')

        save_data(data, username=username)
        flash('Contact information saved successfully', 'success')
        return redirect(url_for('dashboard_contact'))

    return render_template('dashboard/contact.html', data=data)


@app.route('/dashboard/social', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_social():
    """Edit social media links for current user"""
    username = session.get('username')
    data = load_data(username=username)

    if request.method == 'POST':
        if 'social' not in data:
            data['social'] = {}

        data['social']['linkedin'] = request.form.get('linkedin', '')
        data['social']['github'] = request.form.get('github', '')
        data['social']['twitter'] = request.form.get('twitter', '')
        data['social']['instagram'] = request.form.get('instagram', '')
        data['social']['facebook'] = request.form.get('facebook', '')
        data['social']['youtube'] = request.form.get('youtube', '')
        data['social']['behance'] = request.form.get('behance', '')
        data['social']['dribbble'] = request.form.get('dribbble', '')

        save_data(data, username=username)
        flash('Social media links saved successfully', 'success')
        return redirect(url_for('dashboard_social'))

    return render_template('dashboard/social.html', data=data)




@app.route('/dashboard/messages')
@login_required
@disable_in_demo
def dashboard_messages():
    """List all messages for current user with priority filtering"""
    username = session.get('username')
    data = load_data(username=username)
    all_messages = data.get('messages', [])
    
    # Get priority filter from query parameter
    priority_filter = request.args.get('priority', 'all')
    
    # Filter by priority if specified
    if priority_filter != 'all':
        messages = [m for m in all_messages if m.get('priority', 'normal') == priority_filter]
    else:
        messages = all_messages
    
    # Sort by date descending
    messages = sorted(messages, key=lambda x: x.get('date', ''), reverse=True)
    
    # Calculate priority counts for dashboard
    priority_stats = {
        'high': len([m for m in all_messages if m.get('priority') == 'high']),
        'normal': len([m for m in all_messages if m.get('priority', 'normal') == 'normal']),
        'low': len([m for m in all_messages if m.get('priority') == 'low']),
        'total': len(all_messages)
    }
    
    return render_template('dashboard/messages.html', messages=messages, 
                         priority_filter=priority_filter, priority_stats=priority_stats)


@app.route('/dashboard/messages/view/<int:message_id>')
@login_required
def dashboard_view_message(message_id):
    """View specific message for current user"""
    username = session.get('username')
    data = load_data(username=username)
    message = next(
        (m for m in data.get('messages', []) if m.get('id') == message_id),
        None)

    if not message:
        flash('Message not found', 'error')
        return redirect(url_for('dashboard_messages'))

    if not message.get('read', False):
        # We need to update mark_message_as_read to support isolation as well, 
        # but for now we can update the message directly here and save
        message['read'] = True
        save_data(data, username=username)

    return render_template('dashboard/view_message.html', message=message)


@app.route('/dashboard/messages/delete/<int:message_id>')
@login_required
@disable_in_demo
def dashboard_delete_message(message_id):
    """Delete message for current user"""
    username = session.get('username')
    data = load_data(username=username)
    data['messages'] = [
        m for m in data.get('messages', []) if m.get('id') != message_id
    ]
    save_data(data, username=username)
    flash('Message deleted successfully', 'success')
    return redirect(url_for('dashboard_messages'))


@app.route('/dashboard/messages/convert/<int:message_id>')
@login_required
@disable_in_demo
def dashboard_convert_message_to_client(message_id):
    """Convert message to client for current user"""
    username = session.get('username')
    data = load_data(username=username)
    message = next(
        (m for m in data.get('messages', []) if m.get('id') == message_id),
        None)

    if not message:
        flash('Message not found', 'error')
        return redirect(url_for('dashboard_messages'))

    if 'clients' not in data:
        data['clients'] = []

    client_ids = [c.get('id', 0) for c in data.get('clients', [])]
    new_id = max(client_ids) + 1 if client_ids else 1

    new_client = {
        'id': new_id,
        'name': message.get('name', ''),
        'email': message.get('email', ''),
        'phone': '',
        'company': '',
        'project_title': '',
        'project_description': message.get('message', ''),
        'status': 'lead',
        'price': '',
        'deadline': '',
        'start_date': datetime.now().strftime('%Y-%m-%d'),
        'notes': '',
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    data['clients'].append(new_client)
    save_data(data, username=username)

    flash('Message converted to client successfully', 'success')
    return redirect(url_for('dashboard_edit_client', client_id=new_id))


@app.route('/dashboard/clients')
@login_required
@disable_in_demo
def dashboard_clients():
    """List all clients for current user"""
    username = session.get('username')
    data = load_data(username=username)
    if 'clients' not in data:
        data['clients'] = []
        save_data(data, username=username)

    clients = sorted(data.get('clients', []),
                     key=lambda x: x.get('created_at', ''),
                     reverse=True)
    
    stats = get_clients_stats(username)
    return render_template('dashboard/clients.html',
                           clients=clients,
                           stats=stats)


@app.route('/dashboard/clients/add', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_add_client():
    """Add new client for current user"""
    username = session.get('username')
    if request.method == 'POST':
        data = load_data(username=username)

        if 'clients' not in data:
            data['clients'] = []

        client_ids = [c.get('id', 0) for c in data.get('clients', [])]
        new_id = max(client_ids) + 1 if client_ids else 1

        new_client = {
            'id':
            new_id,
            'name':
            request.form.get('name', '').strip(),
            'email':
            request.form.get('email', '').strip(),
            'phone':
            request.form.get('phone', '').strip(),
            'company':
            request.form.get('company', '').strip(),
            'project_title':
            request.form.get('project_title', '').strip(),
            'project_description':
            request.form.get('project_description', '').strip(),
            'status':
            request.form.get('status', 'lead'),
            'price':
            request.form.get('price', '').strip(),
            'deadline':
            request.form.get('deadline', '').strip(),
            'start_date':
            request.form.get('start_date', '').strip()
            or datetime.now().strftime('%Y-%m-%d'),
            'notes':
            request.form.get('notes', '').strip(),
            'created_at':
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status_updated_at':
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        data['clients'].append(new_client)
        save_data(data, username=username)
        
        # Send Telegram notification for new lead (to user's channel)
        send_telegram_notification(
            f"📊 <b>New Lead Added</b>\n\n"
            f"👤 {new_client['name']}\n"
            f"📧 {new_client['email']}\n"
            f"📋 {new_client['project_title']}\n"
            f"💰 ${new_client['price'] if new_client['price'] else 'TBD'}",
            username=username
        )
        
        flash('Client added successfully', 'success')
        return redirect(url_for('dashboard_clients'))

    return render_template('dashboard/add_client.html')


@app.route('/dashboard/clients/edit/<int:client_id>', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_edit_client(client_id):
    """Edit existing client for current user"""
    username = session.get('username')
    data = load_data(username=username)
    client = next(
        (c for c in data.get('clients', []) if c.get('id') == client_id), None)

    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('dashboard_clients'))

    if request.method == 'POST':
        old_status = client.get('status', 'lead')
        new_status = request.form.get('status', 'lead')
        
        client['name'] = request.form.get('name', '').strip()
        client['email'] = request.form.get('email', '').strip()
        client['phone'] = request.form.get('phone', '').strip()
        client['company'] = request.form.get('company', '').strip()
        client['project_title'] = request.form.get('project_title', '').strip()
        client['project_description'] = request.form.get(
            'project_description', '').strip()
        client['status'] = new_status
        client['price'] = request.form.get('price', '').strip()
        client['deadline'] = request.form.get('deadline', '').strip()
        client['start_date'] = request.form.get('start_date', '').strip()
        client['notes'] = request.form.get('notes', '').strip()
        
        if old_status != new_status:
            client['status_updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Send Telegram notification for status change (to user's channel)
            status_emoji = {
                'lead': '🎯',
                'negotiation': '💬',
                'in-progress': '⚙️',
                'delivered': '✅'
            }
            send_telegram_notification(
                f"{status_emoji.get(new_status, '📊')} <b>Client Status Updated</b>\n\n"
                f"👤 {client['name']}\n"
                f"📋 {client['project_title']}\n"
                f"📍 {old_status.title()} → {new_status.replace('-', ' ').title()}\n"
                f"💰 ${client['price'] if client['price'] else 'TBD'}\n"
                f"📝 {client['notes'][:100] if client['notes'] else 'N/A'}",
                username=username
            )

        save_data(data, username=username)
        flash('Client updated successfully', 'success')
        return redirect(url_for('dashboard_clients'))

    return render_template('dashboard/edit_client.html', client=client)


@app.route('/dashboard/clients/view/<int:client_id>')
@login_required
def dashboard_view_client(client_id):
    """View client details for current user"""
    username = session.get('username')
    data = load_data(username=username)
    client = next(
        (c for c in data.get('clients', []) if c.get('id') == client_id), None)

    if not client:
        flash('Client not found', 'error')
        return redirect(url_for('dashboard_clients'))

    return render_template('dashboard/view_client.html', client=client)


@app.route('/dashboard/clients/delete/<int:client_id>')
@login_required
@disable_in_demo
def dashboard_delete_client(client_id):
    """Delete client for current user"""
    username = session.get('username')
    data = load_data(username=username)
    data['clients'] = [
        c for c in data.get('clients', []) if c.get('id') != client_id
    ]
    save_data(data, username=username)
    flash('Client deleted successfully', 'success')
    return redirect(url_for('dashboard_clients'))




@app.route('/dashboard/change-password', methods=['GET', 'POST'])
@login_required
@disable_in_demo
def dashboard_change_password():
    """Change admin password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_password or not check_password_hash(
                ADMIN_CREDENTIALS['password_hash'], current_password):
            flash('Current password is incorrect', 'error')
        elif new_password != confirm_password:
            flash('New password and confirmation do not match', 'error')
        elif not new_password or len(new_password) < 8:
            flash('New password must be at least 8 characters long', 'error')
        else:
            ADMIN_CREDENTIALS['password_hash'] = generate_password_hash(
                new_password)
            flash('Password changed successfully. Please login again.',
                  'success')
            session.clear()
            return redirect(url_for('dashboard_login'))

    return render_template('dashboard/change_password.html')


@app.route('/cv-preview')
@disable_in_demo
def cv_preview():
    """CV preview page for current user or default if not logged in"""
    username = session.get('username', 'admin')
    data = load_data(username=username)
    return render_template('cv_preview.html', data=data)


@app.route('/download-cv')
@disable_in_demo
def download_cv():
    """Download CV as PDF for current user"""
    try:
        import weasyprint
        username = session.get('username', 'admin')
        data = load_data(username=username)
        html_content = render_template('cv_preview.html',
                                       data=data,
                                       pdf_mode=True)

        pdf_buffer = io.BytesIO()
        html = weasyprint.HTML(string=html_content, base_url=request.url_root)
        html.write_pdf(pdf_buffer)
        pdf_buffer.seek(0)

        filename = data.get("name", "CV").replace(' ', '_')
        return send_file(pdf_buffer,
                         mimetype='application/pdf',
                         as_attachment=True,
                         download_name=f'{filename}_CV.pdf')

    except ImportError:
        flash(
            'PDF generation library not available. Please install weasyprint.',
            'error')
        return redirect(url_for('cv_preview'))
    except Exception as e:
        app.logger.error(f"PDF Generation Error: {str(e)}")
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('cv_preview'))


@app.after_request
def add_security_headers(response):
    """Add security headers including Content Security Policy"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://replit-cdn.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors *;"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
