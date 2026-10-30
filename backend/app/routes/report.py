"""
Report Routes - Vulnerability Submissions & Vendor Tracking

Endpoints for submitting vulnerabilities to bug bounty platforms (HackerOne, Bugcrowd, etc.),
tracking vendor interactions, and managing bounty awards.
All org-scoped by organization_id. Requires JWT authentication.

"""

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.report import Report, ReportStatus, ReportPlatform
from app.models.vulnerability import Vulnerability
from app.models.target import Target
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.error_responses import error_response, success_response, paginated_response, ErrorCode
from datetime import datetime
import logging

logger = logging.getLogger("bug_bounty")
report_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    """Extract current user from JWT token."""
    return User.query.get(get_jwt_identity())

def parse_report_platform(value: str):
    """
    Convert a raw string to ReportPlatform BY VALUE (not by member name).
    FIX: the original used ReportPlatform[value.upper()], which only worked
    by coincidence for this particular enum (member names happen to match
    uppercased values). Using ReportPlatform(value) here matches the pattern
    used everywhere else in the codebase (vulnerability_routes.py etc.) and
    won't silently break if a multi-word platform value is ever added.
    """
    try:
        return ReportPlatform(value.lower().strip()), None
    except (ValueError, AttributeError):
        valid = ", ".join(p.value for p in ReportPlatform)
        return None, f"Invalid platform '{value}'. Valid: {valid}"
 
 
def parse_report_status(value: str):
    """Convert a raw string to ReportStatus BY VALUE."""
    try:
        return ReportStatus(value.lower().strip()), None
    except (ValueError, AttributeError):
        valid = ", ".join(s.value for s in ReportStatus)
        return None, f"Invalid status '{value}'. Valid: {valid}"


def validate_report_ownership(report: Report, org_id: str) -> bool:
    """Verify report belongs to user's organization."""
    return report and report.organization_id == org_id and not report.is_deleted


# ==============================================================================
# CREATE REPORT (Submit vulnerability to platform)
# ==============================================================================

@report_bp.route("", methods=["POST"])
@jwt_required()
def create_report():
    """
    POST /api/reports
    
    Submit a vulnerability to a bug bounty platform (HackerOne, Bugcrowd, etc.).
    Creates a Report record linked to a Vulnerability.
    
    Request:
        {
            "vulnerability_id": "vuln-uuid",
            "target_id": "target-uuid",
            "platform": "hackerone",  # hackerone | bugcrowd | yeswehack | intigriti | direct | email
            "title": "Reflected XSS in search parameter",
            "description": "User input is not sanitized in the search endpoint",
            "summary": "Brief summary (optional)",
            "steps_to_reproduce": "1. Go to /search\n2. Enter <img src=x onerror=alert()>",
            "impact": "Attacker can steal user session cookies",
            "remediation": "Use htmlspecialchars() to sanitize user input",
            "payload": {"test": "payload"} (optional),
            "screenshot_urls": ["https://..."] (optional),
            "video_url": "https://..." (optional),
            "poc_url": "https://..." (optional),
            "cvss_score": 7.1 (optional),
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/..." (optional),
            "internal_notes": "Additional notes" (optional)
        }
    
    Response:
        201: {"success": true, "data": {"report": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body required", 400)
        
        # Validate required fields
        required_fields = [
            "vulnerability_id", "target_id", "platform", "title",
            "description", "steps_to_reproduce", "impact"
        ]
        
        for field in required_fields:
            if field not in data or not data[field]:
                return error_response(
                    ErrorCode.MISSING_FIELD,
                    f"{field} field required",
                    400
                )
        
        vulnerability_id = data["vulnerability_id"]
        target_id = data["target_id"]
        platform = data["platform"].lower()
        title = data["title"].strip()
        description = data["description"].strip()
        steps_to_reproduce = data["steps_to_reproduce"].strip()
        impact = data["impact"].strip()
        
        # Validate platform
        platform_enum, err = parse_report_platform(data["platform"])
        if err:
            return error_response(ErrorCode.INVALID_ENUM, err, 400)
        
        # Validate string lengths
        if len(title) < 5 or len(title) > 255:
            return error_response(ErrorCode.INVALID_RANGE, "title must be 5-255 characters", 400)
        
        if len(description) < 10:
            return error_response(ErrorCode.INVALID_RANGE, "description must be >= 10 characters", 400)
        
        if len(steps_to_reproduce) < 10:
            return error_response(ErrorCode.INVALID_RANGE, "steps_to_reproduce must be >= 10 characters", 400)
        
        if len(impact) < 10:
            return error_response(ErrorCode.INVALID_RANGE, "impact must be >= 10 characters", 400)
        
        # Verify vulnerability exists and belongs to org
        vulnerability = Vulnerability.query.filter_by(
            id=vulnerability_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not vulnerability:
            return error_response(ErrorCode.NOT_FOUND, "Vulnerability not found", 404)
        
        # Verify target exists and belongs to org
        target = Target.query.filter_by(
            id=target_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not target:
            return error_response(ErrorCode.NOT_FOUND, "Target not found", 404)
        
        # Check if already submitted to this platform
        existing = Report.query.filter_by(
            vulnerability_id=vulnerability_id,
            platform=platform_enum,
            is_deleted=False
        ).first()
        
        if existing:
            return error_response(
                ErrorCode.ALREADY_EXISTS,
                f"Vulnerability already submitted to {platform}",
                409
            )
        
        # Create report
        report = Report(
            organization_id=org.id,
            user_id=user.id,
            vulnerability_id=vulnerability_id,
            target_id=target_id,
            platform=platform_enum,
            status=ReportStatus.DRAFT,
            title=title,
            description=description,
            steps_to_reproduce=steps_to_reproduce,
            impact=impact,
            remediation=data.get("remediation", "").strip() or None,
            summary=data.get("summary", "").strip() or None,
            payload=data.get("payload"),
            screenshot_urls=data.get("screenshot_urls"),
            video_url=data.get("video_url"),
            poc_url=data.get("poc_url"),
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            internal_notes=data.get("internal_notes")
        )
        
        db.session.add(report)
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.REPORT,
            entity_id=report.id,
            event_type=EventType.OTHER,
            actor_id=user.id,
            source=EventSource.USER,
            payload={"action": "report_created", "platform": platform}
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"User {user.id} created report {report.id} in organization {org.id}")
        
        return success_response(
            {"report": report.to_dict()},
            "Report created",
            201
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to create report", 500)


# ==============================================================================
# LIST REPORTS
# ==============================================================================

@report_bp.route("", methods=["GET"])
@jwt_required()
def list_reports():
    """
    GET /api/reports
    
    List all reports in organization with pagination and filtering.
    
    Query parameters:
        skip: int (default: 0)
        limit: int (default: 50, max: 200)
        status: str (filter by status) [optional]
        platform: str (filter by platform) [optional]
        vulnerability_id: str (filter by vulnerability) [optional]
        target_id: str (filter by target) [optional]
    
    Response:
        200: {
            "success": true,
            "data": {
                "reports": [{...}, ...],
                "pagination": {...}
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
        
        limit = max(1, min(limit, 200))
        
        # Base query
        query = Report.query.filter_by(organization_id=org.id, is_deleted=False)
        
        # Optional filters
        status_filter = request.args.get("status")
        if status_filter:
            try:
                status_enum = ReportStatus[status_filter.upper()]
                query = query.filter_by(status=status_enum)
            except KeyError:
                return error_response(ErrorCode.INVALID_ENUM, "Invalid status value", 400)
        
        platform_filter = request.args.get("platform")
        if platform_filter:
            try:
                platform_enum = ReportPlatform[platform_filter.upper()]
                query = query.filter_by(platform=platform_enum)
            except KeyError:
                return error_response(ErrorCode.INVALID_ENUM, "Invalid platform value", 400)
        
        vulnerability_id = request.args.get("vulnerability_id")
        if vulnerability_id:
            query = query.filter_by(vulnerability_id=vulnerability_id)
        
        target_id = request.args.get("target_id")
        if target_id:
            query = query.filter_by(target_id=target_id)
        
        total = query.count()
        reports = query.order_by(Report.created_at.desc()).offset(skip).limit(limit).all()
        
        return paginated_response(
            [r.to_dict() for r in reports],
            total, skip, limit,
            "Reports retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to list reports: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list reports", 500)


# ==============================================================================
# GET REPORT DETAILS
# ==============================================================================

@report_bp.route("/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    """
    GET /api/reports/<report_id>
    
    Get detailed information about a specific report.
    
    Response:
        200: {"success": true, "data": {"report": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        report = Report.query.filter_by(
            id=report_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not report:
            return error_response(ErrorCode.NOT_FOUND, "Report not found", 404)
        
        return success_response(
            {"report": report.to_dict()},
            "Report retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get report", 500)


# ==============================================================================
# UPDATE REPORT
# ==============================================================================

@report_bp.route("/<report_id>", methods=["PUT"])
@jwt_required()
def update_report(report_id):
    """
    PUT /api/reports/<report_id>
    
    Update report details (notes, tags, etc.).
    Cannot update SUBMITTED or RESOLVED reports (immutable after submission).
    
    Request:
        {
            "internal_notes": "Updated notes",
            "tags": ["critical", "duplicate-risk"],
            "remediation": "Updated remediation info"
        }
    
    Response:
        200: {"success": true, "data": {"report": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        report = Report.query.filter_by(
            id=report_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not report:
            return error_response(ErrorCode.NOT_FOUND, "Report not found", 404)
        
        # Can only edit DRAFT reports
        if report.status != ReportStatus.DRAFT:
            return error_response(
                ErrorCode.CONFLICT,
                f"Cannot edit {report.status.value} reports",
                409
            )
        
        data = request.get_json()
        if not data:
            return error_response(ErrorCode.MISSING_FIELD, "Request body required", 400)
        
        # Whitelist updatable fields for DRAFT
        if "internal_notes" in data:
            report.internal_notes = data["internal_notes"]
        
        if "tags" in data:
            tags = data["tags"]
            if not isinstance(tags, list):
                return error_response(ErrorCode.INVALID_FORMAT, "tags must be an array", 400)
            report.tags = tags
        
        if "remediation" in data:
            report.remediation = data["remediation"].strip() or None
        
        if "summary" in data:
            report.summary = data["summary"].strip() or None
        
        db.session.commit()
        
        logger.info(f"User {user.id} updated report {report.id}")
        
        return success_response(
            {"report": report.to_dict()},
            "Report updated"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to update report", 500)


# ==============================================================================
# SUBMIT REPORT (DRAFT -> SUBMITTED)
# ==============================================================================

@report_bp.route("/<report_id>/submit", methods=["POST"])
@jwt_required()
def submit_report(report_id):
    """
    POST /api/reports/<report_id>/submit
    
    Submit report to vendor (transition DRAFT -> SUBMITTED).
    Sets submitted_at timestamp.
    
    Request (optional):
        {
            "submission_url": "https://hackerone.com/reports/123456"  (optional),
            "submission_id": "H1-123456"  (optional)
        }
    
    Response:
        200: {"success": true, "data": {"report": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        report = Report.query.filter_by(
            id=report_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not report:
            return error_response(ErrorCode.NOT_FOUND, "Report not found", 404)
        
        # Only DRAFT reports can be submitted
        if report.status != ReportStatus.DRAFT:
            return error_response(
                ErrorCode.CONFLICT,
                f"Only DRAFT reports can be submitted (current: {report.status.value})",
                409
            )
        
        data = request.get_json() or {}
        
        # Update submission details if provided
        if "submission_url" in data:
            report.submission_url = data["submission_url"]
        
        if "submission_id" in data:
            report.submission_id = data["submission_id"]
        
        # Mark as submitted
        report.mark_submitted()
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.REPORT,
            entity_id=report.id,
            event_type=EventType.OTHER,
            actor_id=user.id,
            source=EventSource.USER,
            payload={"action": "report_submitted", "platform": report.platform.value}
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"User {user.id} submitted report {report.id} to {report.platform.value}")
        
        return success_response(
            {"report": report.to_dict()},
            "Report submitted to vendor"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to submit report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to submit report", 500)


# ==============================================================================
# ACKNOWLEDGE REPORT (vendor acknowledged)
# ==============================================================================

@report_bp.route("/<report_id>/acknowledge", methods=["PATCH"])
@jwt_required()
def acknowledge_report(report_id):
    """
    PATCH /api/reports/<report_id>/acknowledge
    
    Mark report as acknowledged by vendor.
    Sets is_acknowledged=true and acknowledged_at timestamp.
    
    Request (optional):
        {
            "vendor_response": "We received your report and are investigating.",
            "vendor_comment": "Additional response from vendor"
        }
    
    Response:
        200: {"success": true, "data": {"report": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        report = Report.query.filter_by(
            id=report_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not report:
            return error_response(ErrorCode.NOT_FOUND, "Report not found", 404)
        
        # Can acknowledge SUBMITTED, TRIAGED reports
        if report.status not in [ReportStatus.SUBMITTED, ReportStatus.TRIAGED]:
            return error_response(
                ErrorCode.CONFLICT,
                f"Cannot acknowledge {report.status.value} reports",
                409
            )
        
        data = request.get_json() or {}
        
        if "vendor_response" in data:
            report.vendor_response = data["vendor_response"]
        
        if "vendor_comment" in data:
            report.vendor_comment = data["vendor_comment"]
        
        report.mark_acknowledged()
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.REPORT,
            entity_id=report.id,
            event_type=EventType.OTHER,
            actor_id=user.id,
            source=EventSource.USER,
            payload={"action": "report_acknowledged"}
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"Report {report.id} marked as acknowledged")
        
        return success_response(
            {"report": report.to_dict()},
            "Report marked as acknowledged"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to acknowledge report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to acknowledge report", 500)


# ==============================================================================
# RESOLVE REPORT (award bounty)
# ==============================================================================

@report_bp.route("/<report_id>/resolve", methods=["PATCH"])
@jwt_required()
def resolve_report(report_id):
    """
    PATCH /api/reports/<report_id>/resolve
    
    Mark report as resolved with bounty information.
    Sets is_resolved=true, resolved_at, bounty_amount, etc.
    
    Request:
        {
            "bounty_amount": 500,
            "bounty_currency": "USD",
            "swag_awarded": "HackerOne T-shirt",
            "vendor_response": "Issue fixed in v2.1"
        }
    
    Response:
        200: {"success": true, "data": {"report": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        report = Report.query.filter_by(
            id=report_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not report:
            return error_response(ErrorCode.NOT_FOUND, "Report not found", 404)
        
        # Can resolve ACKNOWLEDGED, TRIAGED reports (not DRAFT)
        if report.status in [ReportStatus.DRAFT, ReportStatus.RESOLVED]:
            return error_response(
                ErrorCode.CONFLICT,
                f"Cannot resolve {report.status.value} reports",
                409
            )
        
        data = request.get_json() or {}
        
        bounty_amount = data.get("bounty_amount", 0)
        try:
            bounty_amount = float(bounty_amount)
        except (TypeError, ValueError):
            return error_response(ErrorCode.INVALID_FORMAT, "bounty_amount must be numeric", 400)
        
        if bounty_amount < 0:
            return error_response(ErrorCode.INVALID_RANGE, "bounty_amount cannot be negative", 400)
        
        bounty_currency = data.get("bounty_currency", "USD").upper()
        if len(bounty_currency) > 10:
            return error_response(ErrorCode.INVALID_FORMAT, "bounty_currency must be <= 10 chars", 400)
        
        if "vendor_response" in data:
            report.vendor_response = data["vendor_response"]
        
        if "swag_awarded" in data:
            report.swag_awarded = data["swag_awarded"]
        
        # Mark as resolved
        report.mark_resolved(bounty_amount, bounty_currency)
        
        # Also update vulnerability with bounty info
        vuln = report.vulnerability
        if vuln and bounty_amount > 0:
            vuln.bounty_awarded = bounty_amount
            vuln.bounty_currency = bounty_currency
        
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.REPORT,
            entity_id=report.id,
            event_type=EventType.VULN_BOUNTY_AWARDED,
            actor_id=user.id,
            source=EventSource.USER,
            payload={
                "action": "report_resolved",
                "bounty_amount": bounty_amount,
                "bounty_currency": bounty_currency
            }
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"Report {report.id} resolved with ${bounty_amount} {bounty_currency}")
        
        return success_response(
            {"report": report.to_dict()},
            f"Report resolved - ${bounty_amount} {bounty_currency} awarded"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to resolve report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to resolve report", 500)


# ==============================================================================
# DELETE REPORT (soft-delete)
# ==============================================================================

@report_bp.route("/<report_id>", methods=["DELETE"])
@jwt_required()
def delete_report(report_id):
    """
    DELETE /api/reports/<report_id>
    
    Soft-delete a report. Only DRAFT or REJECTED reports can be deleted.
    
    Response:
        200: {"success": true, "message": "Report deleted"}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        report = Report.query.filter_by(
            id=report_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not report:
            return error_response(ErrorCode.NOT_FOUND, "Report not found", 404)
        
        # Can only delete DRAFT or REJECTED reports
        if report.status not in [ReportStatus.DRAFT, ReportStatus.REJECTED]:
            return error_response(
                ErrorCode.CONFLICT,
                f"Cannot delete {report.status.value} reports",
                409
            )
        
        report.soft_delete()
        db.session.commit()
        
        logger.info(f"User {user.id} deleted report {report.id}")
        
        return success_response(None, "Report deleted")
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete report: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to delete report", 500)