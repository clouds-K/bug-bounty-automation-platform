"""
Bounty Routes - Production SaaS Bug Bounty Platform

Workflow: PROPOSED -> APPROVED -> PAID, with REJECTED and DISPUTED side states.
Only admins can approve/reject/mark-paid (financial actions). Any authenticated
org member can propose a bounty (e.g. a triager suggesting an amount).

Multi-tenant: organization_id scoping on all queries.
Standardized responses: error_response() / success_response() throughout.
"""

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.services.permissions import require_permission, P
from app.models.user import User
from app.models.bounty import Bounty, BountyStatus, PaymentMethod
from app.services import bounty_service as bs
from app.utils.error_responses import (
    error_response, success_response, paginated_response, ErrorCode
)
from app.utils.exceptions import (
    CrossOrgViolation, NotFoundError, ValidationError, AuthenticationError
)
import logging

logger = logging.getLogger("bug_bounty")
bounty_bp = Blueprint("bounties", __name__, url_prefix="/api/bounties")


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    return User.query.get(get_jwt_identity())


def require_auth() -> User:
    """
    Resolves the JWT identity to a User row, or raises AuthenticationError.

    Usage (replaces the 3-line "if not user: return error_response(...)"
    pattern repeated at the top of every route below):

        user = require_auth()
    """
    user = get_current_user()
    if not user:
        raise AuthenticationError("User not found")
    return user


def is_admin(user: User) -> bool:
    return bool(user) and user.role in ("admin", "superadmin")


def parse_bounty_status(value: str):
    try:
        return BountyStatus(value.lower().strip()), None
    except (ValueError, AttributeError):
        valid = ", ".join(m.value for m in BountyStatus)
        return None, f"Invalid status. Valid: {valid}"


def parse_payment_method(value: str):
    try:
        return PaymentMethod(value.lower().strip()), None
    except (ValueError, AttributeError):
        valid = ", ".join(m.value for m in PaymentMethod)
        return None, f"Invalid payment_method. Valid: {valid}"


# ==============================================================================
# CREATE (propose)
# ==============================================================================

@bounty_bp.route("", methods=["POST"])
@jwt_required()
def propose_bounty():
    """
    Propose a bounty for a vulnerability.

    Request:
        {
            "vulnerability_id": "...",
            "amount": 500,
            "currency": "USD",
            "is_bonus": false,
            "bonus_reason": null
        }
    """
    try:
        user = require_auth()

        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body is required", 400)

        vuln_id = data.get("vulnerability_id")
        if not vuln_id:
            return error_response(ErrorCode.MISSING_FIELD, "vulnerability_id is required", 400)

        if "amount" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "amount is required", 400)

        try:
            amount = float(data["amount"])
        except (TypeError, ValueError):
            return error_response(ErrorCode.INVALID_FORMAT, "amount must be a number", 400)

        currency = data.get("currency", "USD").upper()
        if len(currency) > 10:
            return error_response(ErrorCode.INVALID_FORMAT, "currency must be <= 10 characters", 400)

        bounty = bs.propose_bounty(
            organization_id=user.organization_id,
            vulnerability_id=vuln_id,
            amount=amount,
            currency=currency,
            actor_id=user.id,
            is_bonus=bool(data.get("is_bonus", False)),
            bonus_reason=data.get("bonus_reason"),
        )

        return success_response({"bounty": bounty.to_dict()}, "Bounty proposed", 201)

    except AuthenticationError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except (NotFoundError, ValidationError) as e:
        db.session.rollback()
        return error_response(ErrorCode.VALIDATION_ERROR, str(e), 400)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to propose bounty: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to propose bounty", 500)


# ==============================================================================
# LIST
# ==============================================================================

@bounty_bp.route("", methods=["GET"])
@jwt_required()
def list_bounties():
    """
    List bounties for the current organization.

    Query parameters:
        vulnerability_id, researcher_id, status, skip, limit
    """
    try:
        user = require_auth()

        status = None
        if request.args.get("status"):
            status, err = parse_bounty_status(request.args["status"])
            if err:
                return error_response(ErrorCode.INVALID_ENUM, err, 400)

        query = bs.list_bounties(
            user.organization_id,
            status=status,
            vulnerability_id=request.args.get("vulnerability_id"),
            researcher_id=request.args.get("researcher_id"),
        )

        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(ErrorCode.INVALID_FORMAT, "skip and limit must be integers", 400)

        limit = max(1, min(limit, 200))
        total = query.count()
        bounties = query.order_by(Bounty.created_at.desc()).offset(skip).limit(limit).all()

        return paginated_response([b.to_simple_dict() for b in bounties], total, skip, limit)

    except Exception as e:
        logger.error(f"Failed to list bounties: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list bounties", 500)


# ==============================================================================
# GET ONE
# ==============================================================================

@bounty_bp.route("/<bounty_id>", methods=["GET"])
@jwt_required()
def get_bounty(bounty_id):
    try:
        user = require_auth()

        bounty = bs.get_bounty(bounty_id, user.organization_id)
        if not bounty:
            return error_response(ErrorCode.NOT_FOUND, "Bounty not found", 404)

        return success_response({"bounty": bounty.to_dict()})

    except Exception as e:
        logger.error(f"Failed to get bounty: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to fetch bounty", 500)


# ==============================================================================
# APPROVE — admin only
# ==============================================================================

@bounty_bp.route("/<bounty_id>/approve", methods=["POST"])
@jwt_required()
@require_permission(P.VULN_VERIFY)
def approve_bounty(bounty_id):
    try:
        user = require_auth()

        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN, "Only organization admins can approve bounties", 403
            )
       

        data = request.get_json() or {}
        notes = data.get("notes")

        bounty = bs.approve_bounty(bounty_id, user.organization_id, actor_id=user.id, notes=notes)
        return success_response({"bounty": bounty.to_dict()}, "Bounty approved")

    except AuthenticationError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except NotFoundError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except CrossOrgViolation as e:
        db.session.rollback()
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)
    except ValueError as e:
        db.session.rollback()
        return error_response(ErrorCode.CONFLICT, str(e), 409)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to approve bounty: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to approve bounty", 500)


# ==============================================================================
# REJECT — admin only
# ==============================================================================

@bounty_bp.route("/<bounty_id>/reject", methods=["POST"])
@jwt_required()
@require_permission(P.VULN_VERIFY)
def reject_bounty(bounty_id):
    try:
        user = require_auth()

        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN, "Only organization admins can reject bounties", 403
            )

        data = request.get_json()
        if not data or "reason" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "reason is required", 400)

        bounty = bs.reject_bounty(
            bounty_id, user.organization_id, actor_id=user.id, reason=data["reason"]
        )
        return success_response({"bounty": bounty.to_dict()}, "Bounty rejected")

    except AuthenticationError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except NotFoundError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except CrossOrgViolation as e:
        db.session.rollback()
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)
    except ValueError as e:
        db.session.rollback()
        return error_response(ErrorCode.CONFLICT, str(e), 409)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to reject bounty: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to reject bounty", 500)


# ==============================================================================
# MARK PAID — admin only
# ==============================================================================

@bounty_bp.route("/<bounty_id>/pay", methods=["POST"])
@jwt_required()
@require_permission(P.ORG_BILLING)
def mark_bounty_paid(bounty_id):

    """
    Request:
        {
            "payment_method": "stripe",
            "stripe_payment_intent_id": "pi_..."  (optional, required for stripe)
        }
    """
    try:
        user = require_auth()

        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN, "Only organization admins can mark bounties as paid", 403
            )

        data = request.get_json()
        if not data or "payment_method" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "payment_method is required", 400)

        payment_method, err = parse_payment_method(data["payment_method"])
        if err:
            return error_response(ErrorCode.INVALID_ENUM, err, 400)

        stripe_pi = data.get("stripe_payment_intent_id")
        if payment_method == PaymentMethod.STRIPE and not stripe_pi:
            return error_response(
                ErrorCode.MISSING_FIELD,
                "stripe_payment_intent_id is required when payment_method is 'stripe'",
                400
            )

        bounty = bs.mark_bounty_paid(
            bounty_id, user.organization_id, actor_id=user.id,
            payment_method=payment_method,
            stripe_payment_intent_id=stripe_pi,
        )
        return success_response({"bounty": bounty.to_dict()}, "Bounty marked as paid")

    except AuthenticationError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except NotFoundError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except CrossOrgViolation as e:
        db.session.rollback()
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)
    except ValueError as e:
        db.session.rollback()
        return error_response(ErrorCode.CONFLICT, str(e), 409)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to mark bounty paid: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to mark bounty as paid", 500)


# ==============================================================================
# DISPUTE
# ==============================================================================

@bounty_bp.route("/<bounty_id>/dispute", methods=["POST"])
@jwt_required()
def dispute_bounty(bounty_id):
    try:
        user = require_auth()

        data = request.get_json()
        if not data or "reason" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "reason is required", 400)

        bounty = bs.dispute_bounty(
            bounty_id, user.organization_id, actor_id=user.id, reason=data["reason"]
        )
        return success_response({"bounty": bounty.to_dict()}, "Bounty disputed")

    except AuthenticationError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except NotFoundError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
    except CrossOrgViolation as e:
        db.session.rollback()
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)
    except ValueError as e:
        db.session.rollback()
        return error_response(ErrorCode.CONFLICT, str(e), 409)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to dispute bounty: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to dispute bounty", 500)