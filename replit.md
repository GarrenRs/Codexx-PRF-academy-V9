# Codexx - Portfolio Management Platform

## 📋 Project Overview
**Codexx** is a professional multi-tenant portfolio management platform providing client CRM, analytics, and content management. The platform was built with Flask and uses JSON file storage for flexibility and simplicity.

**Current Status:** Production-ready (payments system removed as per user request)
**Last Updated:** December 29, 2025
**Version:** 1.0.0

---

## 🎯 Project Goals
- Provide professional portfolio hosting and management
- Enable client relationship management (CRM)
- Track portfolio analytics and visitor metrics
- Support multiple portfolio themes and customization
- Multi-tenant architecture with data isolation

---

## 🏗️ Architecture & Systems

### 1. **Authentication System**
- **Type:** Session-based authentication
- **Location:** `app.py` (lines: register, dashboard_login)
- **Features:**
  - Username/password registration and login
  - Password hashing using werkzeug.security
  - Session management with secure cookies (HTTPONLY, SAMESITE)
  - Admin/demo account support
  - Password change functionality
- **Current Issues:**
  - Admin credentials hardcoded (should use environment variables)
  - No 2FA/password reset functionality
  - Single admin model (multi-user not fully implemented)

### 2. **Multi-Tenant Data Architecture**
- **Type:** JSON file-based (`data.json`)
- **Structure:** Per-user portfolio isolation
  ```
  {
    "users": [...],
    "portfolios": {
      "username1": { ...user portfolio data... },
      "username2": { ...user portfolio data... }
    }
  }
  ```
- **Location:** `app.py` (load_data, save_data functions)
- **Advantages:** Simple, no database setup required
- **Limitations:** Not scalable for large datasets

### 3. **Client Management CRM**
- **Stages:** Lead → Negotiation → In Progress → Completed
- **Data Tracked:**
  - Client name, email, phone, company
  - Project description, pricing, deadline
  - Revenue calculations
  - Payment status tracking
- **Location:** Dashboard routes (dashboard_clients, dashboard_add_client, etc.)
- **Current Issues:**
  - Payment status field still references old payment system
  - No automated payment notifications

### 4. **Portfolio Themes System**
- **Theme Count:** 6 professional themes
  1. **Luxury Gold** - Premium, dark mode with gold accents
  2. **Modern Dark** - Sleek, minimalist dark design
  3. **Clean Light** - Bright, professional light theme
  4. **Terracotta Red** - Warm, creative theme
  5. **Vibrant Green** - Fresh, energetic theme
  6. **Silver Grey** - Neutral, corporate theme
- **Theme Files:** `static/themes/*.css`
- **Dark Mode:** Full support across all themes
- **User Customization:** Per-user theme selection stored in settings

### 5. **Notification Systems**

#### 5.1 **Telegram Bot Integration**
- **Configuration File:** `telegram_config.json`
- **Purpose:** Real-time notifications for:
  - New contact form messages
  - Client status changes
  - Portfolio updates
- **Location:** `app.py` (lines: send_telegram_notification, send_telegram_event_notification)
- **Features:**
  - Async notification sending
  - User-specific token support
  - Connection testing capability
- **Status:** Optional (gracefully disabled if not configured)

#### 5.2 **SMTP Email Notifications**
- **Configuration:** Per-user or global SMTP settings
- **Purpose:** HTML-formatted emails for:
  - Contact form submissions
  - Client updates
  - System alerts
- **Features:**
  - Secure credential storage
  - HTML email support
  - User-specific email configuration
  - Settings panel with test functionality

### 6. **Visitor Analytics System**
- **Tracking Data:**
  - IP address (anonymized)
  - User agent
  - Referrer
  - Page path
  - Geolocation (country, city)
  - Timestamp
- **Location:** `app.py` (track_visitor, get_visitor_count functions)
- **Storage:** Data aggregated in user portfolio under "visitors" key
- **Privacy:** IP logging in `security/ip_log.json`

### 7. **Backup & Recovery System**
- **Type:** Automated hourly + manual backups
- **Scheduler:** APScheduler background scheduler
- **Features:**
  - Hourly automatic backups (`scheduled_backup`)
  - Manual backup creation from dashboard
  - Backup restoration with safety backup
  - Metadata tracking (timestamp, size, type)
  - Automatic cleanup (keeps last 20 backups)
- **Location:** 
  - Backups stored in: `backups/` folder
  - Metadata in: `backups/backups.json`
- **Restoration:** Safe backup with confirmation before restore

### 8. **Security System**
- **Rate Limiting:** IP-based rate limiting (10 requests per 60 seconds)
- **IP Logging:** Security audit log in `security/ip_log.json`
- **Security Headers:**
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options: nosniff
  - Strict-Transport-Security (HSTS)
  - HTTPONLY, SAMESITE cookies
- **Location:** `app.py` (check_rate_limit, log_ip_activity, add_security_headers)

### 9. **Contact Form System**
- **Features:**
  - Name, email, message capture
  - IP and user-agent tracking
  - Read/unread status
  - Spam detection capability
  - Database isolation per portfolio
- **Notifications:** Triggers email and Telegram notifications
- **Location:** `/contact` route and dashboard message management

### 10. **Admin Dashboard Features**
- **User Management:** View all system users
- **Settings Management:**
  - Portfolio info (name, title, description, about)
  - Contact info (email, phone, location)
  - Social media links
  - Theme selection
  - Notification setup (Telegram, SMTP)
- **Content Management:**
  - Projects/portfolio management
  - Skill management with proficiency levels
  - Client management
  - Message management
- **Backups:** Create, restore, download, delete backups

---

## 📂 Project Structure

```
codexx/
├── app.py                          # Main Flask application (2194 lines)
├── config.py                       # Configuration management
├── requirements.txt                # Python dependencies
├── data.json                       # Multi-tenant portfolio data
├── telegram_config.json            # Telegram bot credentials
├── backups/                        # Automatic backup storage
│   ├── backup_*.json              # Backup files
│   └── backups.json               # Backup metadata
├── security/                       # Security logs
│   └── ip_log.json               # IP activity log
├── static/
│   ├── themes/                    # 6 professional CSS themes
│   ├── assets/uploads/            # User-uploaded images
│   └── css/                       # Global styles
├── templates/
│   ├── index.html                 # Portfolio public view
│   ├── landing.html               # Home/marketing page
│   ├── catalog.html               # Feature catalog
│   ├── cv_preview.html            # CV/resume preview
│   ├── dashboard/                 # Admin dashboard templates
│   │   ├── base.html              # Dashboard layout
│   │   ├── general.html           # General settings
│   │   ├── about.html             # About section
│   │   ├── projects.html          # Project management
│   │   ├── clients.html           # Client CRM
│   │   ├── contact.html           # Messages
│   │   ├── social.html            # Social links
│   │   ├── settings.html          # Advanced settings
│   │   └── ...                    # Other dashboard pages
│   ├── error/                     # Error pages (400, 403, 404, 500, 503)
│   └── ...                        # Other templates
└── README.md
```

---

## 🔧 Technical Stack

| Component | Technology |
|-----------|-----------|
| **Backend** | Flask 2.x |
| **Database** | JSON files (data.json) |
| **Authentication** | werkzeug.security |
| **Scheduling** | APScheduler |
| **Email** | SMTP (smtplib) |
| **PDF Generation** | WeasyPrint |
| **Frontend Framework** | Bootstrap 5 |
| **Styling** | Custom CSS + SCSS |
| **Icons** | Font Awesome 6 |

---

## 📦 Installed Dependencies

```
email-validator>=2.0.0
flask>=2.0.0
flask-dance>=6.0.0
flask-login>=0.6.0
flask-sqlalchemy>=3.0.0
gunicorn>=21.0.0
oauthlib>=3.2.0
psycopg2-binary>=2.9.0
pyjwt>=2.0.0
weasyprint>=58.0
werkzeug>=2.0.0
apscheduler>=3.10.0
```

---

## 🚨 Known Issues & TODOs

### **Critical Issues**
1. **Admin Credentials Hardcoded**
   - Location: `config.py` and `app.py`
   - Fix: Move to environment variables
   - Status: ⚠️ Security risk

2. **JSON Database Scalability**
   - Issue: data.json becomes slow with many users
   - Solution: Consider PostgreSQL migration
   - Timeline: Post-MVP

3. **Missing Features**
   - OAuth integration (Google, GitHub)
   - Two-factor authentication (2FA)
   - Password reset functionality
   - Email verification

### **Code Quality Issues**
1. **app.py is too large** (2194 lines)
   - Should be split into modules:
     - `routes/auth.py` - Authentication routes
     - `routes/dashboard.py` - Dashboard routes
     - `routes/portfolio.py` - Portfolio routes
     - `utils/notifications.py` - Email/Telegram logic
     - `utils/backup.py` - Backup operations

2. **Payment/Subscription Remnants**
   - ✅ Routes removed
   - ✅ Dashboard links removed
   - ⚠️ Payment_status field still in clients table (unused but present)

3. **Message Routing Logic**
   - Issue: Complex message handling with multiple notification paths
   - Status: Needs refactoring

4. **Demo Mode Logic**
   - Issue: Scattered throughout codebase
   - Status: Needs consolidation

---

## 🔐 Security Checklist

- ✅ Password hashing (werkzeug.security)
- ✅ Session security (HTTPONLY, SAMESITE, SECURE cookies)
- ✅ Rate limiting (IP-based)
- ✅ Security headers (CSP, HSTS, X-Content-Type-Options)
- ✅ SQL injection protection (not using SQL)
- ⚠️ CSRF protection (Flask-WTF recommended)
- ⚠️ Admin credentials should be environment variables
- ⚠️ Email verification for new accounts

---

## 🚀 Deployment Status

- **Server:** Gunicorn on 0.0.0.0:5000
- **Workflow:** Flask App (running)
- **Database:** JSON (data.json)
- **Backups:** Automated hourly + manual
- **Notifications:** Telegram & SMTP enabled

---

## 👤 User Preferences

- **Request:** Complete removal of payment/subscription system
- **Status:** ✅ Completed
- **Implementation:**
  - All payment routes removed
  - Subscription dashboard removed
  - Upgrade/pricing links cleaned
  - Plan selection removed from registration

---

## 📝 System Commands

### Start Application
```bash
gunicorn --bind 0.0.0.0:5000 app:app
```

### Create Manual Backup
```python
create_backup(manual=True)
```

### Test Email Configuration
```python
send_email(recipient, subject, body)
```

### Test Telegram Configuration
```python
send_telegram_notification("Test message")
```

---

## 🔄 Recent Changes (Dec 29, 2025)

- ✅ Removed payment/subscription system completely
- ✅ Cleaned up landing page and dashboard navigation
- ✅ Updated demo mode banner messaging
- ✅ Removed unused SQLAlchemy models (models.py, db_init.py)
- ✅ **Phase 1 Refactoring:** Removed payment_status field from client management (app.py + 3 templates)
- ✅ **Fixed Contact Form Routing:** Messages now correctly route to portfolio owner via portfolio_owner field
  - Updated `index.html` to include portfolio owner name in hidden field
  - Fixed `landing()` and `index()` routes to pass correct data to templates
- 🔄 Phase 2: Consolidate Demo Mode Logic (pending)
- 🔄 Phase 3: Extract utils modules (pending)
- 🔄 Phase 4: Restructure routes (pending)

---

## 📞 Support & Maintenance

- **Bug Reports:** Check logs in `security/ip_log.json`
- **Backup Recovery:** Use backup restoration feature in dashboard
- **Theme Issues:** Check `static/themes/` CSS files
- **Email Issues:** Test via dashboard settings → notifications

---

*Generated: December 29, 2025*
*Platform: Codexx Portfolio Management System v1.0.0*
