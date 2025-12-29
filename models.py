from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.postgresql import JSON
import uuid

db = SQLAlchemy()


class Workspace(db.Model):
    """Workspace model - represents a portfolio workspace"""
    __tablename__ = 'workspaces'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    plan = db.Column(db.String(50), default='free')  # free, pro, enterprise
    
    # Relationships
    users = db.relationship('User', backref='workspace', lazy=True, cascade='all, delete-orphan')
    portfolio_settings = db.relationship('PortfolioSettings', backref='workspace', lazy=True, cascade='all, delete-orphan')
    projects = db.relationship('Project', backref='workspace', lazy=True, cascade='all, delete-orphan')
    clients = db.relationship('Client', backref='workspace', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='workspace', lazy=True, cascade='all, delete-orphan')
    skills = db.relationship('Skill', backref='workspace', lazy=True, cascade='all, delete-orphan')
    visitor_logs = db.relationship('VisitorLog', backref='workspace', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='workspace', lazy=True, cascade='all, delete-orphan')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Workspace {self.name}>'


class User(db.Model):
    """User model - represents a user account"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    
    role = db.Column(db.String(50), default='owner')  # owner, manager, editor, viewer
    is_active = db.Boolean(default=True)
    is_super_admin = db.Boolean(default=False)
    
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.Index('idx_workspace_email', 'workspace_id', 'email'),)
    
    def __repr__(self):
        return f'<User {self.email}>'


class PortfolioSettings(db.Model):
    """Portfolio Settings model - stores portfolio configuration"""
    __tablename__ = 'portfolio_settings'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False, unique=True)
    
    # Basic Info
    name = db.Column(db.String(255))
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    about = db.Column(db.Text)
    photo = db.Column(db.String(500))
    
    # Contact Info
    email = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    location = db.Column(db.String(255))
    
    # Social Links (stored as JSON)
    social_links = db.Column(JSON, default={})
    
    # Theme & Preferences
    theme = db.Column(db.String(50), default='luxury-gold')
    custom_css = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<PortfolioSettings {self.workspace_id}>'


class Project(db.Model):
    """Project model - stores portfolio projects"""
    __tablename__ = 'projects'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    short_description = db.Column(db.String(500))
    content = db.Column(db.Text)
    
    image = db.Column(db.String(500))
    demo_url = db.Column(db.String(500))
    github_url = db.Column(db.String(500))
    
    # Technologies as JSON array
    technologies = db.Column(JSON, default=[])
    
    # Status
    is_published = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.Index('idx_workspace_project', 'workspace_id', 'is_published'),)
    
    def __repr__(self):
        return f'<Project {self.title}>'


class Client(db.Model):
    """Client model - stores client information"""
    __tablename__ = 'clients'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    company = db.Column(db.String(255))
    
    status = db.Column(db.String(50), default='pending')  # pending, active, on-hold, completed
    price = db.Column(db.Float)
    deadline = db.Column(db.Date)
    project_description = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.Index('idx_workspace_client', 'workspace_id', 'status'),)
    
    def __repr__(self):
        return f'<Client {self.name}>'


class Message(db.Model):
    """Message model - stores contact form messages"""
    __tablename__ = 'messages'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    
    is_read = db.Column(db.Boolean, default=False)
    is_spam = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.Index('idx_workspace_message', 'workspace_id', 'is_read'),)
    
    def __repr__(self):
        return f'<Message from {self.email}>'


class Skill(db.Model):
    """Skill model - stores portfolio skills"""
    __tablename__ = 'skills'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    
    name = db.Column(db.String(255), nullable=False)
    level = db.Column(db.Integer, default=50)  # 0-100
    category = db.Column(db.String(100))
    order = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (db.Index('idx_workspace_skill', 'workspace_id', 'category'),)
    
    def __repr__(self):
        return f'<Skill {self.name}>'


class VisitorLog(db.Model):
    """Visitor Log model - tracks visitor analytics"""
    __tablename__ = 'visitor_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500))
    referer = db.Column(db.String(500))
    path = db.Column(db.String(500))
    
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_workspace_visitor', 'workspace_id', 'created_at'),
        db.Index('idx_visitor_ip', 'ip_address'),
    )
    
    def __repr__(self):
        return f'<VisitorLog {self.ip_address}>'


class AuditLog(db.Model):
    """Audit Log model - tracks all system changes"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    
    action = db.Column(db.String(100), nullable=False)  # created, updated, deleted, login, etc
    resource_type = db.Column(db.String(100))  # Project, Client, Message, etc
    resource_id = db.Column(db.String(36))
    
    old_values = db.Column(JSON)  # previous values for updates
    new_values = db.Column(JSON)  # new values for updates
    
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.Index('idx_audit_workspace_action', 'workspace_id', 'action'),
        db.Index('idx_audit_user_action', 'user_id', 'action'),
    )
    
    def __repr__(self):
        return f'<AuditLog {self.action}>'
