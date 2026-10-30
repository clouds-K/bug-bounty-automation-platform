"""
Target Routes - Production SaaS Bug Bounty Platform

Gestion des cibles (programmes bug bounty).

Multi-tenant: organization_id scoping on all queries.
Soft-delete: targets are never hard-deleted, just marked is_deleted=True.
Standardized responses: ALL endpoints use error_response() / success_response().

Routes are thin controllers: authenticate, parse the request, call
target_service, translate the result (or exception) into a response.
All validation, normalization, duplicate detection, and domain-sync
logic now lives in target_service.py — see that file for details.
"""

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.target import Target
from app.models.exploit import Exploit
from app.models.report import Report
from app.services import target_service as ts
from app.utils.error_responses import (
    error_response,
    success_response,
    paginated_response,
    ErrorCode
)
from app.utils.exceptions import CrossOrgViolation
import logging

logger = logging.getLogger("bug_bounty")
target_bp = Blueprint("targets", __name__, url_prefix="/api/targets")


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    """Resolve JWT identity to User object."""
    user_id = get_jwt_identity()
    return User.query.get(user_id)


# ==============================================================================
# CREATE
# ==============================================================================

@target_bp.route("", methods=["POST"])
@jwt_required()
def create_target():
    """
    Create a new bug bounty target (program).

    Request:
        {
            "scan_url": "http://localhost:8081",   # REQUIRED — exact scan target URL
            "program_name": "Example Bug Bounty",
            "platform": "hackerone",
            "program_url": "https://hackerone.com/example",
            "scope": "Web application",
            "in_scope": ["*.example.com", "/api/*"],
            "out_of_scope": ["/admin", "*.internal.example.com"],
            "rewards_min": 100,
            "rewards_max": 5000,
            "notes": "Optional notes",
            "asset_type": "web",
            "scan_enabled": true,
            "scan_config": {"rate_limit": 10, "timeout_minutes": 30}
        }

    Response (201):
        {
            "success": true,
            "data": { "target": {...} },
            "message": "Target created successfully",
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

    logger.info("User %s creating target", user.id)

    target_data = {
        "organization_id": user.organization_id,
        "user_id": user.id,
        "scan_url": data.get("scan_url", ""),
        "program_name": data.get("program_name"),
        "platform": data.get("platform", "custom"),
        "program_url": data.get("program_url"),
        "scope": data.get("scope"),
        "in_scope": data.get("in_scope"),
        "out_of_scope": data.get("out_of_scope"),
        "rewards_min": data.get("rewards_min", 0),
        "rewards_max": data.get("rewards_max", 0),
        "notes": data.get("notes"),
        "asset_type": data.get("asset_type"),
        "scan_enabled": data.get("scan_enabled", True),
        "scan_config": data.get("scan_config"),
        "status": "active"
    }

    try:
        target_data["rewards_min"] = float(target_data["rewards_min"])
        target_data["rewards_max"] = float(target_data["rewards_max"])
    except (TypeError, ValueError):
        return error_response(
            ErrorCode.VALIDATION_ERROR, "rewards_min and rewards_max must be numbers", 400
        )

    try:
        target = ts.create_target(target_data, actor_id=user.id)
        return success_response(
            {"target": target.to_dict()}, "Target created successfully", 201
        )

    except ValueError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e), 400)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create target: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to create target", 500)


# ==============================================================================
# LIST
# ==============================================================================

@target_bp.route("", methods=["GET"])
@jwt_required()
def list_targets():
    """
    List all targets for current organization.

    Query parameters:
        - skip: number of records to skip (default 0)
        - limit: number of records to return (default 50, max 200)
        - status: filter by status (active, inactive, etc.)
        - platform: filter by platform (hackerone, bugcrowd, custom, etc.)

    Response (200):
        {
            "success": true,
            "data": [
                {"id": "...", "scan_url": "...", "domain": "...", ...},
                ...
            ],
            "pagination": {
                "skip": 0,
                "limit": 50,
                "total": 123,
                "count": 50,
                "has_more": true
            },
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        status = request.args.get("status")
        platform = request.args.get("platform")

        query = ts.list_targets(user.organization_id, status=status, platform=platform)

        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(
                ErrorCode.INVALID_FORMAT, "skip and limit must be integers", 400
            )

        limit = max(1, min(limit, 200))  # Hard cap to prevent abuse
        total = query.count()
        targets = query.order_by(Target.created_at.desc()).offset(skip).limit(limit).all()

        return paginated_response(
            [t.to_simple_dict() for t in targets], total, skip, limit
        )

    except Exception as e:
        logger.error(f"Failed to list targets: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list targets", 500)


# ==============================================================================
# GET ONE
# ==============================================================================

@target_bp.route("/<target_id>", methods=["GET"])
@jwt_required()
def get_target(target_id):
    """
    Get a single target by ID.

    Response (200):
        {
            "success": true,
            "data": {
                "target": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "organization_id": "...",
                    "scan_url": "http://localhost:8081",
                    "domain": "localhost",
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

        target = ts.get_target(target_id, user.organization_id)
        if not target:
            return error_response(
                ErrorCode.NOT_FOUND, "Target not found", 404, {"target_id": target_id}
            )

        return success_response({"target": target.to_dict()})

    except Exception as e:
        logger.error(f"Failed to get target: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to fetch target", 500)


# ==============================================================================
# UPDATE
# ==============================================================================

@target_bp.route("/<target_id>", methods=["PUT"])
@jwt_required()
def update_target(target_id):
    """
    Update target fields.

    Request:
        {
            "scan_url": "https://staging.example.com",
            "program_name": "New Name",
            "rewards_min": 200,
            "rewards_max": 10000,
            "scan_enabled": false,
            "scan_config": {"rate_limit": 5, "timeout_minutes": 15},
            "notes": "Updated notes",
            ...
        }

    Response (200):
        {
            "success": true,
            "data": { "target": {...} },
            "message": "Target updated successfully",
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

    logger.info("User %s updating target %s", user.id, target_id)

    try:
        target = ts.update_target(
            target_id, user.organization_id, data, actor_id=user.id
        )
        if not target:
            return error_response(
                ErrorCode.NOT_FOUND, "Target not found", 404, {"target_id": target_id}
            )

        return success_response(
            {"target": target.to_dict()}, "Target updated successfully", 200
        )

    except ValueError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e), 400)

    except CrossOrgViolation as e:
        db.session.rollback()
        logger.warning(f"CrossOrgViolation: {e}")
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update target: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to update target", 500)


# ==============================================================================
# DELETE (SOFT)
# ==============================================================================

@target_bp.route("/<target_id>", methods=["DELETE"])
@jwt_required()
def delete_target(target_id):
    """
    Soft-delete a target (marks is_deleted=True, not hard-deleted).

    Response (200):
        {
            "success": true,
            "message": "Target deleted successfully",
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        target = ts.delete_target(target_id, user.organization_id, actor_id=user.id)
        if not target:
            return error_response(
                ErrorCode.NOT_FOUND, "Target not found", 404, {"target_id": target_id}
            )

        return success_response(None, "Target deleted successfully", 200)

    except CrossOrgViolation as e:
        db.session.rollback()
        logger.warning(f"CrossOrgViolation: {e}")
        return error_response(ErrorCode.FORBIDDEN, str(e), 403)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete target: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to delete target", 500)


# ==============================================================================
# STATS
# ==============================================================================

@target_bp.route("/<target_id>/stats", methods=["GET"])
@jwt_required()
def target_stats(target_id):
    """
    Get comprehensive statistics for a target.

    Returns cached counters (vuln_count_total, vuln_count_critical, etc.)
    maintained by Target.update_vuln_stats() + scan tracking.

    Response (200):
        {
            "success": true,
            "data": {
                "vulnerabilities_count": 42,
                "vulnerabilities_critical": 3,
                "vulnerabilities_high": 7,
                "exploits_count": 5,
                "reports_count": 15,
                "sla_breached_count": 1,
                "avg_fix_time_hours": 48.5,
                "last_scan_at": "2026-06-15T10:30:00",
                "last_scan_status": "completed"
            },
            "request_id": "uuid",
            "timestamp": "iso8601"
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        target = ts.get_target(target_id, user.organization_id)
        if not target:
            return error_response(
                ErrorCode.NOT_FOUND, "Target not found", 404, {"target_id": target_id}
            )

        # Refresh cached counters on-demand (cheap: COUNT queries scoped to this target)
        target.update_vuln_stats()
        db.session.commit()

        exploit_count = Exploit.query.filter_by(
            organization_id=user.organization_id, target_id=target_id
        ).count()
        report_count = Report.query.filter_by(
            organization_id=user.organization_id, target_id=target_id, is_deleted=False
        ).count()

        stats = {
            "vulnerabilities_count": target.vuln_count_total,
            "vulnerabilities_critical": target.vuln_count_critical,
            "vulnerabilities_high": target.vuln_count_high,
            "exploits_count": exploit_count,
            "reports_count": report_count,
            "sla_breached_count": target.sla_breached_count,
            "avg_fix_time_hours": target.avg_fix_time_hours,
            "last_scan_at": target.last_scan_at.isoformat() if target.last_scan_at else None,
            "last_scan_status": target.last_scan_status,
        }

        return success_response(stats)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to fetch target stats: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to fetch stats", 500)
    # ==============================================================================
# GENERATE PDF REPORT
# ==============================================================================

@target_bp.route("/<target_id>/generate-report", methods=["POST"])
@jwt_required()
def generate_report(target_id):
    """
    Dispatch asynchronous PDF vulnerability report generation for a target.

    WHY ASYNC: PDF generation uses WeasyPrint, which depends on native
    GTK/Pango libraries only reliably available on the Linux Celery
    worker (Ubuntu), not on this Windows Flask process -- same reasoning
    as why Nuclei scans run via Celery instead of inline. This route
    only dispatches the task and returns immediately; poll task status
    via Celery's AsyncResult (see report status endpoint, if added) or
    check the worker logs for now during development.

    Response (202):
        {
            "success": true,
            "data": { "task_id": "..." },
            "message": "Génération du rapport en cours",
            ...
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        target = ts.get_target(target_id, user.organization_id)
        if not target:
            return error_response(
                ErrorCode.NOT_FOUND, "Target not found", 404, {"target_id": target_id}
            )

        from celery_app import celery
        task = celery.send_task(
            "reports.generate_pdf",
            args=[target_id, user.organization_id]
        )

        logger.info(f"User {user.id} dispatched PDF report generation for target {target_id}")

        return success_response(
            {"task_id": task.id}, "Génération du rapport en cours", 202
        )

    except Exception as e:
        logger.error(f"Failed to dispatch PDF report generation: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to generate report", 500)
    
    # ==============================================================================
# CHECK PDF REPORT STATUS
# ==============================================================================

@target_bp.route("/report-status/<task_id>", methods=["GET"])
@jwt_required()
def report_status(task_id):
    """
    Poll the status of a PDF generation task dispatched via
    /generate-report. Frontend polls this until status == "completed".

    Response (200):
        { "data": { "status": "pending" | "completed" | "failed" } }
    """
    from celery_app import celery
    result = celery.AsyncResult(task_id)

    if result.state == "PENDING" or result.state == "STARTED":
        status = "pending"
    elif result.state == "SUCCESS":
        status = "completed"
    elif result.state == "FAILURE":
        status = "failed"
    else:
        status = result.state.lower()

    return success_response({"status": status})


# ==============================================================================
# DOWNLOAD GENERATED PDF REPORT
# ==============================================================================

@target_bp.route("/report-download/<task_id>", methods=["GET"])
@jwt_required()
def report_download(task_id):
    """
    Downloads the PDF once /report-status/<task_id> shows "completed".
    Decodes the base64 PDF bytes from the Celery result (see
    report_tasks.py for why base64-in-result is used instead of a file
    path) and streams them to the browser.
    """
    import base64
    from io import BytesIO
    from flask import send_file
    from celery_app import celery

    result = celery.AsyncResult(task_id)

    if result.state != "SUCCESS":
        return error_response(
            ErrorCode.CONFLICT, f"Report not ready (status: {result.state})", 409
        )

    payload = result.result
    pdf_bytes = base64.b64decode(payload["pdf_base64"])
    filename = payload.get("filename", "security_report.pdf")

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
    
    