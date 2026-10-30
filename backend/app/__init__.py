"""
Flask Application Factory - Production SaaS Bug Bounty Platform

This module creates and configures the Flask application with all extensions,
error handlers, JWT callbacks, and blueprints.

Entry point: create_app("development")

Architecture:
    1. Extensions initialized (db, jwt, migrate, limiter, celery)
    2. Error handlers registered (400, 401, 403, 404, 429, 500)
    3. JWT callbacks registered (user lookup, claims, blocklist)
    4. Blueprints registered (10 API routes)
    5. Logging setup (file-based)
"""

import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


from config import config


# ==============================================================================
# EXTENSIONS — Module-level singletons
# ==============================================================================
# These are initialized without an app here, then bound via .init_app()
# in create_app(). This pattern allows imports from anywhere:
#   from app import db, limiter
# ==============================================================================

db = SQLAlchemy()
"""SQLAlchemy database instance"""

jwt = JWTManager()
"""JWT authentication manager"""

migrate = Migrate()
"""Flask-Migrate database migrations"""

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
"""Rate limiter with IP-based tracking"""


# ==============================================================================
# APPLICATION FACTORY
# ==============================================================================

def create_app(config_name: str = "development") -> Flask:
    """
    Create and configure the Flask application.

    This factory pattern allows creating multiple app instances with different
    configurations (development, testing, production).

    Args:
        config_name (str): Configuration name from config.py
                          Options: "development", "testing", "production"

    Returns:
        Flask: Configured Flask application instance

    Example:
        app = create_app("development")
        with app.app_context():
            db.create_all()
    """

    # ── Create Flask app instance ──────────────────────────────────────────
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # ── Initialize Flask extensions ────────────────────────────────────────
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # ── Initialize Celery for async tasks ──────────────────────────────────
    # CRITICAL: This binds Celery tasks to Flask app context
    # Without this, Celery workers cannot access database (db.session, models)
    from celery_app import init_celery
    init_celery(app)

    # ── Configure CORS (allow frontend requests) ───────────────────────────
    CORS(
        app,
        origins=app.config.get(
            "CORS_ORIGINS",
            ["http://localhost:3000", "http://localhost:3001"]
        ),
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    )

    # ── Register all handlers and blueprints ────────────────────────────────
    register_error_handlers(app)
    register_jwt_handlers(app)
    register_blueprints(app)
    setup_logging(app)

    # ── Development only: auto-create tables ───────────────────────────────
    if config_name == "development":
        with app.app_context():
            db.create_all()
            logger = logging.getLogger("bug_bounty")
            logger.info("Development mode: created tables if missing")

    return app


# ==============================================================================
# ERROR HANDLERS
# ==============================================================================
# Global error handlers for common HTTP error codes
# ==============================================================================

def register_error_handlers(app: Flask):
    """
    Register global error handlers for HTTP error codes.

    Maps HTTP status codes to standardized error responses using error_response().
    """

    from app.utils.error_responses import error_response, ErrorCode

    @app.errorhandler(400)
    def handle_bad_request(e):
        """400: Client sent malformed request"""
        return error_response(
            ErrorCode.VALIDATION_ERROR,
            "Bad request: invalid JSON or missing required fields",
            400
        )

    @app.errorhandler(401)
    def handle_unauthorized(e):
        """401: Missing or invalid authentication"""
        return error_response(
            ErrorCode.UNAUTHORIZED,
            "Authentication required. Provide valid JWT token.",
            401
        )

    @app.errorhandler(403)
    def handle_forbidden(e):
        """403: Authenticated but not authorized for resource"""
        return error_response(
            ErrorCode.FORBIDDEN,
            "Access denied. Insufficient permissions.",
            403
        )

    @app.errorhandler(404)
    def handle_not_found(e):
        """404: Resource not found"""
        return error_response(
            ErrorCode.NOT_FOUND,
            "Resource not found",
            404
        )

    @app.errorhandler(429)
    def handle_rate_limit_exceeded(e):
        """429: Rate limit exceeded"""
        return error_response(
            ErrorCode.PLAN_LIMIT_EXCEEDED,
            "Too many requests. Slow down. Rate limit: 200/day, 50/hour per IP",
            429
        )

    @app.errorhandler(500)
    def handle_internal_error(e):
        """500: Internal server error"""
        db.session.rollback()
        return error_response(
            ErrorCode.INTERNAL_ERROR,
            "Internal server error. Check logs for details.",
            500
        )


# ==============================================================================
# JWT CALLBACKS
# ==============================================================================
# Configure JWT authentication behavior
# ==============================================================================

def register_jwt_handlers(app: Flask):
    """
    Register JWT callbacks for authentication.

    Handles:
    - User lookup from JWT identity
    - Additional claims (role, permissions)
    - Token blacklist checking (TODO)
    """

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """
        Load user from database using JWT identity (user_id).

        Called when @jwt_required() decorator needs the user object.
        Returns None if user not found (allows custom error handling).
        """
        from app.models.user import User
        user_id = jwt_data["sub"]
        return User.query.get(user_id)

    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        """
        Add custom claims to JWT payload.

        Used for authorization checks without extra DB queries.
        Available in routes via get_jwt_claims().
        """
        from app.models.user import User

        user = User.query.get(identity)

        if not user:
            return {}

        return {
            "role": user.role,
            "organization_id": str(user.organization_id) if user.organization_id else None,
        }

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """
        Check if token is in blacklist (revoked/logged out).

        TODO: Implement token blacklist for logout functionality
        - Store revoked token JTI in Redis or database
        - Check on every request
        - Expire old entries after token expiration
        """
        # Placeholder: no blacklist yet
        return False


# ==============================================================================
# BLUEPRINTS
# ==============================================================================
# Register all API route blueprints (10 total)
# ==============================================================================

def register_blueprints(app: Flask):
    """
    Register all API blueprints.

    Blueprints are modular route groups. Each blueprint handles a domain:
    - auth: Authentication (register, login, refresh, logout)
    - target: Program/domain management
    - scan: Vulnerability scan orchestration
    - vulnerability: Finding storage and triage
    - exploit: Proof-of-concept tracking
    - bounty: Reward management
    - billing: Payment and subscription
    - organization: Team and multi-tenant management
    - report: Vulnerability submission to platforms
    - event: Audit trail and analytics

    URL patterns: /api/{domain}/{endpoint}
    """

    # Authentication
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)
    # Routes: /api/auth/register, /api/auth/login, /api/auth/refresh, /api/auth/logout, /api/auth/me

    # Targets (programs to scan)
    from app.routes.target import target_bp
    app.register_blueprint(target_bp)
    # Routes: /api/targets, /api/targets/<id>, /api/targets/<id>/vulns, etc.

    # Scans (vulnerability discovery jobs)
    from app.routes.scan import scan_bp
    app.register_blueprint(scan_bp)
    # Routes: /api/scans, /api/scans/<id>, /api/scans/<id>/progress, etc.

    # Vulnerabilities (security findings)
    from app.routes.vulnerability import vuln_bp
    app.register_blueprint(vuln_bp)
    # Routes: /api/vulnerabilities, /api/vulnerabilities/<id>, /api/vulnerabilities/<id>/triage, etc.

    # Exploits (proof of concept)
    from app.routes.exploit import exploit_bp
    app.register_blueprint(exploit_bp)
    # Routes: /api/exploits, /api/exploits/<id>, /api/exploits/<id>/verify, etc.

    # Bounties (reward tracking)
    from app.routes.bounty import bounty_bp
    app.register_blueprint(bounty_bp)
    # Routes: /api/bounties, /api/bounties/<id>/approve, /api/bounties/<id>/pay, etc.

    # Billing (Stripe integration)
    from app.routes.billing import billing_bp
    app.register_blueprint(billing_bp)
    # Routes: /api/billing/subscribe, /api/billing/webhook, /api/billing/invoice, etc.

    # Organization (team management)
    from app.routes.organization import org_bp
    app.register_blueprint(org_bp)
    # Routes: /api/organizations/me, /api/organizations/me/members, /api/organizations/me/subscription, etc.

    # Reports (vulnerability submissions)
    from app.routes.report import report_bp
    app.register_blueprint(report_bp)
    # Routes: /api/reports, /api/reports/<id>/submit, /api/reports/<id>/resolve, etc.

    # Events (audit trail and analytics)
    from app.routes.event import event_bp
    app.register_blueprint(event_bp)
    # Routes: /api/events, /api/events/<id>, /api/events/stats, etc.


# ==============================================================================
# LOGGING
# ==============================================================================
# Set up file-based logging for production debugging
# ==============================================================================

def setup_logging(app: Flask):
    """
    Configure application logging.

    Logs to:
    - File: logs/app.log (persistent)
    - Console: via logger.info() calls

    Format: [TIMESTAMP] LEVEL in module: message
    """

    os.makedirs("logs", exist_ok=True)

    logger = logging.getLogger("bug_bounty")
    logger.setLevel(logging.INFO)

    # Only add handler once (avoid duplicates on app reload)
    if not logger.handlers:
        file_handler = logging.FileHandler("logs/app.log")
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.info("=" * 80)
    logger.info(f"Application started successfully in {app.config.get('ENV')} mode")
    logger.info(f"Database: {app.config.get('SQLALCHEMY_DATABASE_URI')[:50]}...")
    logger.info(f"CORS origins: {app.config.get('CORS_ORIGINS')}")
    logger.info("=" * 80)