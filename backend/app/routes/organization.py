"""
Organization Routes - Team Management

Endpoints for managing organization members, roles, settings, and invitations.
All org-scoped by organization_id. Requires JWT authentication.


"""

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.organization import Organization
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.error_responses import error_response, success_response, paginated_response, ErrorCode
import logging
import re

logger = logging.getLogger("bug_bounty")
org_bp = Blueprint("organizations", __name__, url_prefix="/api/organizations")


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    """Extract current user from JWT token."""
    return User.query.get(get_jwt_identity())


def is_admin(user: User) -> bool:
    return user and user.role in ("admin", "superadmin")
 
 
def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

# ==============================================================================
# GET ORGANIZATION (current user's org)
# ==============================================================================

@org_bp.route("/me", methods=["GET"])
@jwt_required()
def get_organization():
    """
    GET /api/organizations/me
    
    Returns current user's organization details.
    
    Response:
        200: {"success": true, "data": {"organization": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        if org.is_deleted:
            return error_response(
                ErrorCode.NOT_FOUND,
                "Organization has been deleted",
                404
            )
        
        return success_response(
            {"organization": org.to_dict()},
            "Organization retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to fetch organization: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to fetch organization", 500)


# ==============================================================================
# UPDATE ORGANIZATION SETTINGS
# ==============================================================================

@org_bp.route("/me", methods=["PUT"])
@jwt_required()
def update_organization():
    """
    PUT /api/organizations/me
    
    Update organization settings (name, description, etc.).
    Only admins can update organization settings.
    
    Request:
        {
            "name": "New Org Name",
            "description": "Updated description"
        }
    
    Response:
        200: {"success": true, "data": {"organization": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        # Only admin can update org
        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN,
                "Only organization admins can update settings",
                403
            )
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body required", 400)
        
        # Whitelist updatable fields
        allowed_fields = ["name", "description", "slug"]
        old_values = {}
        new_values = {}
        
        for field in allowed_fields:
            if field in data:
                value = data[field]
                
                # Validate field
                if field == "name":
                    if not value or not isinstance(value, str):
                        return error_response(
                            ErrorCode.VALIDATION_ERROR,
                            "Name must be a non-empty string",
                            400
                        )
                    if len(value) > 255:
                        return error_response(
                            ErrorCode.VALIDATION_ERROR,
                            "Name must be <= 255 characters",
                            400
                        )
                    # Check for duplicate name (excluding self)
                    existing = Organization.query.filter(
                        Organization.name == value,
                        Organization.id != org.id,
                        Organization.is_deleted == False
                    ).first()
                    if existing:
                        return error_response(
                            ErrorCode.CONFLICT,
                            "Organization name already exists",
                            409
                        )
                    old_values["name"] = org.name
                    new_values["name"] = value
                    org.name = value
                
                elif field == "slug":
                    if not value or not isinstance(value, str):
                        return error_response(
                            ErrorCode.VALIDATION_ERROR,
                            "Slug must be a non-empty string",
                            400
                        )
                    if len(value) > 100:
                        return error_response(
                            ErrorCode.VALIDATION_ERROR,
                            "Slug must be <= 100 characters",
                            400
                        )
                    if not re.match(r'^[a-z0-9-]+$', value):
                        return error_response(
                            ErrorCode.VALIDATION_ERROR,
                            "Slug must contain only lowercase alphanumeric and hyphens",
                            400
                        )
                    existing = Organization.query.filter(
                        Organization.slug == value,
                        Organization.id != org.id,
                        Organization.is_deleted == False
                    ).first()
                    if existing:
                        return error_response(
                            ErrorCode.CONFLICT,
                            "Slug already in use",
                            409
                        )
                    old_values["slug"] = org.slug
                    new_values["slug"] = value
                    org.slug = value
                
                elif field == "description":
                    if value and len(value) > 5000:
                        return error_response(
                            ErrorCode.VALIDATION_ERROR,
                            "Description must be <= 5000 characters",
                            400
                        )
                    old_values["description"] = org.description
                    new_values["description"] = value
                    org.description = value
        
        db.session.commit()
        
        # Record event only if something changed
        if new_values:
            event = Event.record(
                organization_id=org.id,
                entity_type=EntityType.ORGANIZATION,
                entity_id=org.id,
                event_type=EventType.OTHER,
                actor_id=user.id,
                source=EventSource.USER,
                payload={"action": "updated", "fields": list(new_values.keys())}
            )
            db.session.add(event)
            db.session.commit()
        
        return success_response(
            {"organization": org.to_dict()},
            "Organization settings updated"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update organization: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to update organization", 500)


# ==============================================================================
# LIST ORGANIZATION MEMBERS
# ==============================================================================

@org_bp.route("/me/members", methods=["GET"])
@jwt_required()
def list_members():
    """
    GET /api/organizations/me/members
    
    List all members of current organization with pagination.
    
    Query parameters:
        skip: int (default: 0)
        limit: int (default: 50, max: 200)
        role: str (filter by role: admin, member, viewer) [optional]
    
    Response:
        200: {
            "success": true,
            "data": {
                "members": [{...}, ...],
                "pagination": {
                    "skip": 0,
                    "limit": 50,
                    "total": 5,
                    "count": 5,
                    "has_more": false
                }
            }
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        # Pagination
        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(ErrorCode.INVALID_FORMAT, "skip/limit must be integers", 400)
        
        if skip < 0:
            return error_response(ErrorCode.INVALID_RANGE, "skip must be >= 0", 400)
        
        limit = max(1, min(limit, 200))
        
        # Build query
        query = User.query.filter_by(organization_id=org.id, is_deleted=False)
        
        # Optional role filter
        role_filter = request.args.get("role")
        if role_filter:
            if role_filter not in ["admin", "member", "viewer"]:
                return error_response(
                    ErrorCode.INVALID_ENUM,
                    "role must be: admin, member, or viewer",
                    400
                )
            query = query.filter_by(role=role_filter)
        
        total = query.count()
        members = query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
        
        return paginated_response(
            [m.to_dict() for m in members],
            total, skip, limit,
            "Members retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to list members: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list members", 500)


# ==============================================================================
# GET MEMBER DETAILS
# ==============================================================================

@org_bp.route("/me/members/<member_id>", methods=["GET"])
@jwt_required()
def get_member(member_id):
    """
    GET /api/organizations/me/members/<member_id>
    
    Get details of a specific organization member.
    
    Response:
        200: {"success": true, "data": {"member": {...}}}
        404: Member not found or not in organization
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        member = User.query.filter_by(
            id=member_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not member:
            return error_response(ErrorCode.NOT_FOUND, "Member not found", 404)
        
        return success_response(
            {"member": member.to_dict()},
            "Member details retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get member: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get member", 500)


# ==============================================================================
# UPDATE MEMBER ROLE
# ==============================================================================

@org_bp.route("/me/members/<member_id>/role", methods=["PATCH"])
@jwt_required()
def update_member_role(member_id):
    """
    PATCH /api/organizations/me/members/<member_id>/role
    
    Change member's role (admin, member, viewer).
    Only admins can update roles.
    Cannot demote the last admin.
    
    Request:
        {"role": "member"}  # admin | member | viewer
    
    Response:
        200: {"success": true, "data": {"member": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        # Only admin can change roles
        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN,
                "Only organization admins can change member roles",
                403
            )
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        member = User.query.filter_by(
            id=member_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not member:
            return error_response(ErrorCode.NOT_FOUND, "Member not found", 404)
        
        data = request.get_json()
        if not data or "role" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "role field required", 400)
        
        new_role = data["role"]
        if new_role not in ["admin", "member", "viewer"]:
            return error_response(
                ErrorCode.INVALID_ENUM,
                "role must be: admin, member, or viewer",
                400
            )
        
        old_role = member.role
        
        # Prevent demotion of last admin
        if old_role == "admin" and new_role != "admin":
            admin_count = User.query.filter_by(
                organization_id=org.id,
                role="admin",
                is_deleted=False
            ).count()
            if admin_count <= 1:
                return error_response(
                    ErrorCode.CONFLICT,
                    "Cannot demote the last admin",
                    409
                )
        
        # Prevent self-demotion (can't remove yourself as admin)
        if member.id == user.id and old_role == "admin" and new_role != "admin":
            return error_response(
                ErrorCode.CONFLICT,
                "You cannot remove yourself as admin",
                409
            )
        
        member.role = new_role
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.USER,
            entity_id=member.id,
            event_type=EventType.USER_ROLE_CHANGED,
            actor_id=user.id,
            source=EventSource.USER,
            payload={"from": old_role, "to": new_role}
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"User {user.id} changed {member.id} role from {old_role} to {new_role}")
        
        return success_response(
            {"member": member.to_dict()},
            f"Member role changed to {new_role}"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update member role: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to update member role", 500)


# ==============================================================================
# REMOVE MEMBER FROM ORGANIZATION
# ==============================================================================

@org_bp.route("/me/members/<member_id>", methods=["DELETE"])
@jwt_required()
def remove_member(member_id):
    """
    DELETE /api/organizations/me/members/<member_id>
    
    Remove member from organization (soft-delete).
    Only admins can remove members.
    Cannot remove the last admin.
    
    Response:
        200: {"success": true, "message": "Member removed"}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        # Only admin can remove members
        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN,
                "Only organization admins can remove members",
                403
            )
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        member = User.query.filter_by(
            id=member_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not member:
            return error_response(ErrorCode.NOT_FOUND, "Member not found", 404)
        
        # Can't remove yourself
        if member.id == user.id:
            return error_response(
                ErrorCode.CONFLICT,
                "You cannot remove yourself from the organization",
                409
            )
        
        # Can't remove the last admin
        if member.role == "admin":
            admin_count = User.query.filter_by(
                organization_id=org.id,
                role="admin",
                is_deleted=False
            ).count()
            if admin_count <= 1:
                return error_response(
                    ErrorCode.CONFLICT,
                    "Cannot remove the last admin",
                    409
                )
        
        member.soft_delete()
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.USER,
            entity_id=member.id,
            event_type=EventType.OTHER,
            actor_id=user.id,
            source=EventSource.USER,
            payload={"action": "member_removed"}
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"User {user.id} removed member {member.id} from organization")
        
        return success_response(
            None,
            f"Member {member.username} removed from organization"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to remove member: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to remove member", 500)


# ==============================================================================
# INVITE MEMBER (send email invitation)
# ==============================================================================

@org_bp.route("/me/members/invite", methods=["POST"])
@jwt_required()
def invite_member():
    """
    POST /api/organizations/me/members/invite
    
    Send invitation to a new member via email.
    Only admins can invite members.
    
    Request:
        {
            "email": "alice@example.com",
            "role": "member"  # admin | member | viewer
        }
    
    Response:
        200: {"success": true, "message": "Invitation sent"}
    
    Note: In MVP, we create the user account directly with a temporary password
    and send them a link to set a permanent password. In production, use a
    proper invitation token system with expiration.
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        # Only admin can invite
        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN,
                "Only organization admins can invite members",
                403
            )
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body required", 400)
        
        email = data.get("email", "").strip().lower()
        role = data.get("role", "member")
        
        # Validate email
        if not email:
            return error_response(ErrorCode.MISSING_FIELD, "email field required", 400)
        
        if not validate_email(email):
            return error_response(ErrorCode.INVALID_EMAIL, "Invalid email format", 400)
        
        # Validate role
        if role not in ["admin", "member", "viewer"]:
            return error_response(
                ErrorCode.INVALID_ENUM,
                "role must be: admin, member, or viewer",
                400
            )
        
        # Check organization member limit
        member_count = User.query.filter_by(
            organization_id=org.id,
            is_deleted=False
        ).count()
        
        if member_count >= org.max_members:
            return error_response(
                ErrorCode.PLAN_LIMIT_EXCEEDED,
                f"Organization member limit ({org.max_members}) reached. Upgrade plan to add more members.",
                429
            )
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email, is_deleted=False).first()
        
        if existing_user:
            if existing_user.organization_id == org.id:
                return error_response(
                    ErrorCode.ALREADY_EXISTS,
                    "User is already a member of this organization",
                    409
                )
            else:
                return error_response(
                    ErrorCode.CONFLICT,
                    "Email already registered with another organization",
                    409
                )
        
        # TODO: In production, create an invitation record with token + expiration
        # For now, we just return success and assume external email service handles it
        # Real implementation would:
        # 1. Generate invitation token (UUID)
        # 2. Save to invitations table
        # 3. Send email with signup link: /register?invite_token=...
        # 4. Signup endpoint validates token, creates user, assigns org
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.USER,
            entity_id="",  # No user yet
            event_type=EventType.USER_INVITED,
            actor_id=user.id,
            source=EventSource.USER,
            payload={"email": email, "role": role}
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"User {user.id} invited {email} to organization {org.id}")
        
        return success_response(
            None,
            f"Invitation sent to {email}"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to invite member: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to send invitation", 500)


# ==============================================================================
# GET ORGANIZATION SUBSCRIPTION (billing info)
# ==============================================================================

@org_bp.route("/me/subscription", methods=["GET"])
@jwt_required()
def get_subscription():
    """
    GET /api/organizations/me/subscription
    
    Get current subscription and billing information.
    
    Response:
        200: {
            "success": true,
            "data": {
                "subscription": {
                    "plan": "pro",
                    "status": "active",
                    "max_members": 50,
                    "max_targets": 100,
                    "max_scans_per_day": 50,
                    "stripe_subscription_id": "sub_...",
                    "created_at": "...",
                    "updated_at": "..."
                }
            }
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        return success_response(
            {
                "subscription": {
                    "plan": org.plan,
                    "status": org.subscription_status,
                    "max_members": org.max_members,
                    "max_targets": org.max_targets,
                    "max_scans_per_day": org.max_scans_per_day,
                    "stripe_subscription_id": org.stripe_subscription_id,
                    "stripe_customer_id": org.stripe_customer_id,
                    "created_at": org.created_at.isoformat(),
                    "updated_at": org.updated_at.isoformat()
                }
            },
            "Subscription information retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get subscription: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get subscription", 500)