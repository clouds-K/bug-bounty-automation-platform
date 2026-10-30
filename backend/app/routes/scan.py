"""
Scan Routes - Production SaaS Bug Bounty Platform

Manages security scan execution against targets.

Multi-tenant: organization_id scoping on all queries.
Async: Scans dispatched to Celery worker (optional, graceful fallback if unavailable).
Standardized responses: ALL endpoints use error_response() / success_response().

WORKER CALLBACK SECURITY:
  PATCH /<scan_id>/status was previously gated only by @jwt_required(),
  which meant ANY authenticated user in an org could mark ANY scan in
  that org as completed/failed/cancelled with fabricated results -- not
  just their own. This is now gated by a shared-secret header
  (X-Worker-Secret) instead of a user JWT, since this endpoint represents
  a worker reporting progress, not a user taking an action.

  This is a stepping stone, not the final design described in the
  original TODO (HMAC-signed requests with a timestamp to prevent
  replay). Treat SCAN_WORKER_SECRET as a real secret: long, random,
  stored in your env/secrets manager, never committed, and rotated if it
  ever leaks. If/when an external (non-Celery) worker is introduced,
  upgrade this to the HMAC(scan_id + timestamp + secret) scheme the
  original comment described.
"""

import os
import hmac
from functools import wraps

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.target import Target
from app.services import scan_service as ss
from app.utils.error_responses import (
    error_response,
    success_response,
    paginated_response,
    ErrorCode
)
from app.utils.exceptions import CrossOrgViolation

try:
    from celery_app import celery
    CELERY_AVAILABLE = True
except ImportError:
    celery = None
    CELERY_AVAILABLE = False

import logging

logger = logging.getLogger("bug_bounty")
scan_bp = Blueprint("scans", __name__, url_prefix="/api/scans")


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    """Resolve JWT identity to User object."""
    user_id = get_jwt_identity()
    return User.query.get(user_id)


def get_target(target_id: str, organization_id: str):
    """Org-scoped target lookup."""
    return Target.query.filter_by(
        id=target_id,
        organization_id=organization_id,
        is_deleted=False
    ).first()


def parse_scan_type(value):
    """Convert string to ScanType enum, defaulting to FULL."""
    if value is None:
        return ScanType.FULL, None
    try:
        return ScanType(str(value).lower().strip()), None
    except ValueError:
        valid = ", ".join(m.value for m in ScanType)
        return None, f"Invalid scan_type. Valid: {valid}"


def parse_scan_status(value: str):
    """Convert string to ScanStatus enum."""
    try:
        return ScanStatus(str(value).lower().strip()), None
    except (ValueError, AttributeError):
        valid = ", ".join(m.value for m in ScanStatus)
        return None, f"Invalid status. Valid: {valid}"


def verify_worker_secret(view_func):
    """
    Gates a route behind a shared-secret header instead of a user JWT.
    Expects:
        X-Worker-Secret: <value of SCAN_WORKER_SECRET env var>

    Fails CLOSED: if SCAN_WORKER_SECRET isn't configured in the
    environment, every request is rejected (500) rather than silently
    accepting unauthenticated callers because a secret was never set.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        expected = os.getenv("SCAN_WORKER_SECRET")
        if not expected:
            logger.error(
                "SCAN_WORKER_SECRET is not configured — refusing worker callback"
            )
            return error_response(
                ErrorCode.INTERNAL_ERROR,
                "Worker callback is not configured",
                500
            )

        provided = request.headers.get("X-Worker-Secret", "")
        if not hmac.compare_digest(provided, expected):
            logger.warning("Rejected worker callback with invalid X-Worker-Secret")
            return error_response(
                ErrorCode.FORBIDDEN,
                "Invalid or missing worker credentials",
                403
            )

        return view_func(*args, **kwargs)

    return wrapper


# ==============================================================================
# CREATE
# ==============================================================================

@scan_bp.route("", methods=["POST"])
@jwt_required()
def create_scan():
    """
    Create and queue a new security scan.

    Request:
        {
            "target_id": "550e8400-e29b-41d4-a716-446655440000",
            "scan_type": "full",  # or "quick", optional (defaults to FULL)
            "tools": ["nuclei", "nmap"],  # optional (defaults to ["nuclei"])
            "config": {"timeout": 3600}  # optional, tool-specific config
        }

    Response (201):
        {
            "success": true,
            "data": { "scan": {...}, "worker_dispatched": true },
            "message": "Scan queued successfully",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    user = get_current_user()
    if not user:
        return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

    data = request.get_json()
    if not data:
        return error_response(ErrorCode.MISSING_FIELD, "Request body is required", 400)

    target_id = data.get("target_id")
    if not target_id:
        return error_response(
            ErrorCode.MISSING_FIELD, "target_id is required", 400, {"field": "target_id"}
        )

    scan_type, err = parse_scan_type(data.get("scan_type"))
    if err:
        return error_response(ErrorCode.INVALID_ENUM, err, 400)

    tools = data.get("tools", ["nuclei"])
    if not isinstance(tools, list):
        return error_response(ErrorCode.INVALID_FORMAT, "tools must be a list", 400)

    scan_data = {
        "organization_id": user.organization_id,
        "user_id": user.id,
        "target_id": target_id,
        "scan_type": scan_type,
        "tools": tools,
        "config": data.get("config", {}),
        "status": ScanStatus.QUEUED,
        "progress": 0
    }

    try:
        scan = ss.create_scan(scan_data, actor_id=user.id)

    except ValueError as e:
        # target not found / target paused / quota exceeded
        return error_response(ErrorCode.VALIDATION_ERROR, str(e), 400)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create scan: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to create scan", 500)

    # Dispatch to Celery worker (if configured) — infra concern, stays in
    # the route rather than the service, same reasoning as request-shape
    # validation staying in the route.
    worker_dispatched = False
    if CELERY_AVAILABLE:
        try:
            celery.send_task(
                "scanner.run_scan",
                args=[scan.id, target_id, user.organization_id, user.id, tools,scan.scan_type.value]
            )
            worker_dispatched = True
        except Exception as e:
            logger.warning(f"Failed to dispatch scan to worker: {e}")
            worker_dispatched = False

    return success_response(
        {"scan": scan.to_dict(), "worker_dispatched": worker_dispatched},
        "Scan queued successfully",
        201
    )


# ==============================================================================
# LIST
# ==============================================================================

@scan_bp.route("", methods=["GET"])
@jwt_required()
def list_scans():
    """
    List scans for current organization.

    Query parameters:
        - skip: number of records to skip (default 0)
        - limit: number of records to return (default 50, max 200)
        - target_id: filter by target
        - status: filter by status (queued, running, completed, failed, cancelled)

    Response (200):
        {
            "success": true,
            "data": [
                {"id": "...", "status": "completed", ...},
                ...
            ],
            "pagination": {...},
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        status = None
        if request.args.get("status"):
            status, err = parse_scan_status(request.args["status"])
            if err:
                return error_response(ErrorCode.INVALID_ENUM, err, 400)

        query = ss.list_scans(
            user.organization_id,
            status=status,
            target_id=request.args.get("target_id")
        )

        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(
                ErrorCode.INVALID_FORMAT, "skip and limit must be integers", 400
            )

        limit = max(1, min(limit, 200))
        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()

        return paginated_response(
            [s.to_simple_dict() for s in scans], total, skip, limit
        )

    except Exception as e:
        logger.error(f"Failed to list scans: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list scans", 500)


# ==============================================================================
# GET ONE
# ==============================================================================

@scan_bp.route("/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    """
    Get a single scan by ID.

    Response (200):
        {
            "success": true,
            "data": {
                "scan": {
                    "id": "...",
                    "status": "completed",
                    "progress": 100,
                    ...
                }
            },
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        scan = ss.get_scan(scan_id, user.organization_id)
        if not scan:
            return error_response(
                ErrorCode.NOT_FOUND, "Scan not found", 404, {"scan_id": scan_id}
            )

        return success_response({"scan": scan.to_dict()})

    except Exception as e:
        logger.error(f"Failed to get scan: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to fetch scan", 500)


# ==============================================================================
# CANCEL
# ==============================================================================

@scan_bp.route("/<scan_id>/cancel", methods=["POST"])
@jwt_required()
def cancel_scan(scan_id):
    """
    Cancel a running or queued scan.

    Response (200):
        {
            "success": true,
            "data": { "scan": {...} },
            "message": "Scan cancelled",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    user = get_current_user()
    if not user:
        return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

    try:
        scan = ss.cancel_scan(scan_id, user.organization_id, actor_id=user.id)
        if not scan:
            return error_response(
                ErrorCode.NOT_FOUND, "Scan not found", 404, {"scan_id": scan_id}
            )

        # TODO: Signal Celery worker to stop the running task
        # (celery.control.revoke(task_id, terminate=True)) if task_id tracked

        return success_response({"scan": scan.to_dict()}, "Scan cancelled", 200)

    except ValueError as e:
        # already in a terminal state
        return error_response(ErrorCode.CONFLICT, str(e), 409)

    except CrossOrgViolation as e:
        db.session.rollback()
        logger.warning(f"CrossOrgViolation: {e}")
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to cancel scan: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to cancel scan", 500)


# ==============================================================================
# WORKER CALLBACK — UPDATE SCAN STATUS/PROGRESS
# ==============================================================================
# Called by the scanning worker to report progress/completion. Gated by
# verify_worker_secret (see helper above) instead of @jwt_required() — a
# normal user JWT no longer grants access to this endpoint.
# ==============================================================================

@scan_bp.route("/<scan_id>/status", methods=["PATCH"])
@verify_worker_secret
def update_scan_status(scan_id):
    """
    Update scan status and progress (called by worker).

    Request:
        {
            "organization_id": "...",     # REQUIRED — no user JWT to derive it from
            "status": "completed",        # or "running", "failed", "cancelled"
            "progress": 100,               # 0-100, optional
            "vulnerabilities_found": 42,   # when status=completed
            "error_message": "..."         # when status=failed
        }

    Response (200):
        {
            "success": true,
            "data": { "scan": {...} },
            "message": "Scan updated",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        data = request.get_json()
        if not data or "status" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "status is required", 400)

        organization_id = data.get("organization_id")
        if not organization_id:
            return error_response(
                ErrorCode.MISSING_FIELD, "organization_id is required", 400
            )

        new_status, err = parse_scan_status(data["status"])
        if err:
            return error_response(ErrorCode.INVALID_ENUM, err, 400)

        update_data = {"status": new_status}

        if "vulnerabilities_found" in data:
            try:
                update_data["vulnerabilities_found"] = int(data["vulnerabilities_found"])
            except (TypeError, ValueError):
                return error_response(
                    ErrorCode.INVALID_FORMAT,
                    "vulnerabilities_found must be an integer",
                    400
                )

        if "error_message" in data:
            update_data["error_message"] = data["error_message"]

        if "progress" in data:
            try:
                progress = int(data["progress"])
                if not (0 <= progress <= 100):
                    return error_response(
                        ErrorCode.INVALID_RANGE, "progress must be between 0 and 100", 400
                    )
                update_data["progress"] = progress
            except (TypeError, ValueError):
                return error_response(
                    ErrorCode.INVALID_FORMAT, "progress must be an integer", 400
                )

        scan = ss.update_scan_status(scan_id, organization_id, update_data)
        if not scan:
            return error_response(
                ErrorCode.NOT_FOUND, "Scan not found", 404, {"scan_id": scan_id}
            )

        return success_response({"scan": scan.to_dict()}, "Scan updated", 200)

    except CrossOrgViolation as e:
        db.session.rollback()
        logger.warning(f"CrossOrgViolation: {e}")
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update scan status: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to update scan", 500)