"""
Auth Routes - Production SaaS Bug Bounty Platform

Every signup creates a new Organization (tenant) where the registering
user becomes the first member with role="admin". This is the standard
B2B SaaS pattern — every customer has their own isolated workspace.

All responses use standardized error_response() / success_response()
matching the format used by target, vulnerability, and scan routes.

INCLUDES:
- Token refresh endpoint
- Rate limiting (prevent brute force & spam)
"""

from flask import Blueprint, request



from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
) 

from app import db, limiter
from app.models.user import User
from app.models.organization import Organization
from app.utils.error_responses import error_response, success_response, ErrorCode
from datetime import datetime
from flask import Blueprint, request, make_response
import re
import logging

logger = logging.getLogger("bug_bounty")
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ==============================================================================
# VALIDATION HELPERS
# ==============================================================================

def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email))


def validate_password(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, "ok"


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "org"


def unique_slug(base: str) -> str:
    """Ensure Organization.slug is unique — append a number suffix if needed."""
    slug = slugify(base)
    candidate = slug
    suffix = 0
    while Organization.query.filter_by(slug=candidate).first() is not None:
        suffix += 1
        candidate = f"{slug}-{suffix}"
    return candidate


# ==============================================================================
# REGISTER
# ==============================================================================

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("3 per hour")  # Prevent spam registrations
def register():
    """
    Register a new user and auto-create their organization (workspace).

    Request:
        {
            "username": "alice",
            "email": "alice@company.com",
            "password": "SecurePass123",
            "organization_name": "Acme Corp"  (optional)
        }

    Response (201):
        {
            "success": true,
            "data": { "user": {...}, "organization": {...} },
            "message": "User and organization created successfully",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body is required", 400)

        username = data.get("username", "").strip()
        email    = data.get("email", "").strip().lower()
        password = data.get("password", "")
        org_name = data.get("organization_name", "").strip()

        # --- Presence check ---
        missing = [f for f in ["username", "email", "password"] if not data.get(f, "").strip()]
        if missing:
            return error_response(
                ErrorCode.MISSING_FIELD,
                "username, email, and password are required",
                400,
                {"missing_fields": missing}
            )

        # --- Format validation ---
        if not validate_email(email):
            return error_response(ErrorCode.INVALID_EMAIL, "Invalid email format", 400, {"email": email})

        valid, msg = validate_password(password)
        if not valid:
            return error_response(ErrorCode.INVALID_PASSWORD, msg, 400)

        # --- Uniqueness check ---
        # Note: uniqueness is per-organization (uq_username_org / uq_email_org),
        # but since each signup creates a new org, a global check here is a fast-fail
        # UX guard only — the DB constraint is the real safety net.
        if User.query.filter_by(username=username).first():
            return error_response(
                ErrorCode.USERNAME_ALREADY_EXISTS,
                f"Username '{username}' is already taken",
                409,
                {"username": username}
            )

        if User.query.filter_by(email=email).first():
            return error_response(
                ErrorCode.EMAIL_ALREADY_EXISTS,
                f"Email '{email}' is already registered",
                409,
                {"email": email}
            )

        # --- Create organization ---
        if not org_name:
            org_name = f"{username}'s Organization"

        org = Organization(name=org_name, slug=unique_slug(org_name), plan="free")
        db.session.add(org)
        db.session.flush()  # get org.id without full commit

        # --- Create user as org admin ---
        user = User(
            organization_id=org.id,
            username=username,
            email=email,
            role="admin",  # org creator is always the org admin
            plan="free"
        )
        user.set_password(password)
        user.generate_api_key()

        db.session.add(user)
        db.session.commit()

        return success_response(
            {"user": user.to_dict(), "organization": org.to_dict()},
            "User and organization created successfully",
            201
        )

    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to create user", 500)


# ==============================================================================
# LOGIN
# ==============================================================================

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # Prevent brute force attacks
def login():
    """
    Authenticate with email or username, receive JWT access + refresh tokens.

    Request:
        {
            "identifier": "alice@company.com",  # email OR username
            "password": "SecurePass123"
        }

    Response (200):
        {
            "success": true,
            "data": { 
                "access_token": "eyJ...",
                "refresh_token": "eyJ...",
                "user": {...} 
            },
            "message": "Login successful",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body is required", 400)

        identifier = data.get("identifier", "").strip()
        password   = data.get("password", "")

        if not identifier or not password:
            return error_response(
                ErrorCode.MISSING_FIELD,
                "identifier and password are required",
                400
            )

        # --- Look up user by email or username ---
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        # --- Password check (record failed attempt for non-existent users too) ---
        if not user or not user.check_password(password):
            if user:
                user.record_failed_login()
                db.session.commit()
            # Generic message — don't reveal whether the account exists
            return error_response(
                ErrorCode.INVALID_CREDENTIALS,
                "Invalid email/username or password",
                401
            )

        # --- Account state checks ---
        if user.is_deleted:
            return error_response(ErrorCode.ACCOUNT_DELETED, "This account has been deleted", 403)

        if not user.is_active:
            return error_response(ErrorCode.ACCOUNT_DISABLED, "This account is disabled", 403)

        if user.is_locked():
            return error_response(
                ErrorCode.ACCOUNT_LOCKED,
                "Account is temporarily locked. Try again later.",
                403,
                {"locked_until": user.locked_until.isoformat() if user.locked_until else None}
            )

        # --- Organization state check ---
        if user.organization_id and user.organization:
            if user.organization.is_deleted or not user.organization.is_active:
                return error_response(
                    ErrorCode.ACCOUNT_DISABLED,
                    "Your organization has been disabled. Contact support.",
                    403
                )

       # --- Issue JWT tokens ---
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        user.reset_failed_logins()
        user.last_login_at = datetime.utcnow()
        db.session.commit()

        response = make_response(success_response(
            {"user": user.to_dict()},
            "Login successful"
        ))
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        return response

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        logger.error(f"Login failed: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Login failed", 500)


# ==============================================================================
# ME
# ==============================================================================

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """
    Get the current authenticated user's profile and organization.

    Headers:
        Authorization: Bearer <access_token>

    Response (200):
        {
            "success": true,
            "data": {
                "user": {...},
                "organization": {...}
            },
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        if user.is_deleted:
            return error_response(ErrorCode.ACCOUNT_DELETED, "This account has been deleted", 403)

        data = {"user": user.to_dict()}
        if user.organization:
            data["organization"] = user.organization.to_dict()

        return success_response(data)

    except Exception as e:
        logger.error(f"Failed to fetch current user: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to fetch user", 500)


# ==============================================================================
# REFRESH TOKEN
# ==============================================================================

@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit("10 per minute")  # Allow more refreshes than login attempts
@jwt_required(refresh=True)
def refresh():
    """
    POST /api/auth/refresh

    Exchange a valid refresh token for a new access token.
    
    The refresh token is long-lived (30 days per config.py).
    The access token is short-lived (1 hour per config.py).
    
    When the access token expires, use this endpoint with the refresh token
    to get a new access token without re-entering credentials.

    Headers:
        Authorization: Bearer <refresh_token>

    Response (200):
        {
            "success": true,
            "data": { "access_token": "eyJ..." },
            "message": "Token refreshed",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }

    Example flow:
        1. User logs in with /login
           → Get access_token (1 hour) + refresh_token (30 days)
        2. User calls API with access_token
           → Works fine for 1 hour
        3. After 1 hour, access_token expires
           → Call /refresh with refresh_token
           → Get new access_token (another 1 hour)
        4. Repeat step 2-3 for up to 30 days
        5. After 30 days, refresh_token expires
           → User must log in again with /login
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if not user or user.is_deleted or not user.is_active:
            return error_response(ErrorCode.UNAUTHORIZED, "Account not found or disabled", 401)

        new_access_token = create_access_token(identity=user_id)

        response = make_response(success_response(None, "Token refreshed"))
        set_access_cookies(response, new_access_token)
        return response

    except Exception as e:
        logger.error(f"Token refresh failed: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to refresh token", 500)


# ==============================================================================
# LOGOUT (optional - tokens expire automatically)
# ==============================================================================

@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    POST /api/auth/logout
    
    Optional: Log out the user (mainly for client-side token cleanup).
    
    In a JWT-based system, tokens are stateless and expire automatically.
    This endpoint is mostly for logging intent. In production, you might:
    - Track logged-out tokens in a blacklist
    - Clear client-side session data
    - Record a logout event
    
    Headers:
        Authorization: Bearer <access_token>

    Response (200):
        {
            "success": true,
            "message": "Logged out successfully"
        }
    """
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)

        if user:
            user.last_logout_at = datetime.utcnow()
            db.session.commit()

        response = make_response(success_response(None, "Logged out successfully"))
        unset_jwt_cookies(response)
        return response

    except Exception as e:
        logger.error(f"Logout failed: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Logout failed", 500)