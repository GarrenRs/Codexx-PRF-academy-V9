"""Database initialization and migration helpers"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from models import db, Workspace, User, PortfolioSettings, Project, Client, Message, Skill, VisitorLog, AuditLog


def init_db(app: Flask):
    """Initialize database with app context"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created successfully")
        
        # Check if demo workspace exists
        demo_workspace = Workspace.query.filter_by(slug='demo').first()
        if not demo_workspace:
            # Create demo workspace for migration
            demo_workspace = Workspace(
                name='Demo Portfolio',
                slug='demo',
                description='Default workspace created during migration',
                plan='free'
            )
            db.session.add(demo_workspace)
            
            # Create default admin user for demo workspace
            from werkzeug.security import generate_password_hash
            admin_user = User(
                workspace_id=demo_workspace.id,
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                first_name='Admin',
                last_name='User',
                role='owner',
                is_active=True,
                is_super_admin=False
            )
            db.session.add(admin_user)
            
            # Create portfolio settings for demo workspace
            portfolio_settings = PortfolioSettings(
                workspace_id=demo_workspace.id,
                name='Demo Portfolio',
                theme='luxury-gold'
            )
            db.session.add(portfolio_settings)
            
            db.session.commit()
            print("✅ Demo workspace created successfully")
        else:
            print("ℹ️  Demo workspace already exists")


def get_or_create_demo_workspace():
    """Get or create demo workspace for backward compatibility"""
    demo_workspace = Workspace.query.filter_by(slug='demo').first()
    if not demo_workspace:
        demo_workspace = Workspace(
            name='Demo Portfolio',
            slug='demo',
            description='Default workspace',
            plan='free'
        )
        db.session.add(demo_workspace)
        db.session.commit()
    return demo_workspace


def get_workspace_by_id(workspace_id):
    """Get workspace by ID"""
    return Workspace.query.get(workspace_id)


def get_user_by_workspace(workspace_id, username):
    """Get user by workspace and username"""
    return User.query.filter_by(workspace_id=workspace_id, username=username).first()
