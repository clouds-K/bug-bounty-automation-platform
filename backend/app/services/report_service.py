"""
Report Service - Production SaaS Bug Bounty Platform

Mirrors the pattern established in vulnerability_service.py:
- Org-scoped queries everywhere
- Event recording on every write operation
- Single transaction per operation
- Keeps Vulnerability.bounty_awarded in sync when a report is resolved
"""

from app import db
from app.models.report import Report, ReportStatus, ReportPlatform
from app.models.vulnerability import Vulnerability
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.exceptions import CrossOrgViolation, NotFoundError, ValidationError


def _assert_same_org(report: Report, organization_id: str):
    if report.organization_id != organization_id:
        raise CrossOrgViolation(
            f"Report {report.id} does not belong to organization {organization_id}"
        )


def _assert_not_deleted(report: Report):
    if report.is_deleted:
        raise NotFoundError("Report has been deleted")


# ==============================================================================
# READ
# ==============================================================================

def get_report(report_id: str, organization_id: str) -> Report:
    """Org-scoped, non-deleted report lookup."""
    return Report.query.filter_by(
        id=report_id,
        organization_id=organization_id,
        is_deleted=False
    ).first()


def list_reports(organization_id: str, status: ReportStatus = None,
                  platform: ReportPlatform = None, vulnerability_id: str = None,
                  target_id: str = None):
    """
    Org-scoped, non-deleted report list with optional filters.

    Usage:
        reports = list_reports(org_id, status=ReportStatus.SUBMITTED)
        for r in reports.all():
            ...
    """
    query = Report.query.filter_by(
        organization_id=organization_id,
        is_deleted=False
    )

    if status:
        query = query.filter_by(status=status)
    if platform:
        query = query.filter_by(platform=platform)
    if vulnerability_id:
        query = query.filter_by(vulnerability_id=vulnerability_id)
    if target_id:
        query = query.filter_by(target_id=target_id)

    return query


# ==============================================================================
# WRITE — CREATE
# ==============================================================================

def create_report(report_data: dict, actor_id: str) -> Report:
    """
    Creates a new Report (status=DRAFT), validates that the linked
    vulnerability and target belong to the same org, checks for duplicate
    submissions to the same platform, and records a creation Event.

    report_data MUST include:
        organization_id, user_id, vulnerability_id, target_id,
        platform (ReportPlatform), title, description,
        steps_to_reproduce, impact

    Usage:
        report = create_report({
            "organization_id": user.organization_id,
            "user_id": user.id,
            "vulnerability_id": vuln.id,
            "target_id": vuln.target_id,
            "platform": ReportPlatform.HACKERONE,
            "title": "Reflected XSS in /search",
            "description": "...",
            "steps_to_reproduce": "1. Go to /search ...",
            "impact": "Session hijacking possible",
        }, actor_id=user.id)
    """
    organization_id = report_data.get("organization_id")
    vulnerability_id = report_data.get("vulnerability_id")
    platform = report_data.get("platform")

    # Verify vulnerability belongs to org
    vuln = Vulnerability.query.filter_by(
        id=vulnerability_id,
        organization_id=organization_id,
        is_deleted=False
    ).first()
    if vuln is None:
        raise NotFoundError("Vulnerability not found in this organization")

    # Check for duplicate submission to same platform
    existing = Report.query.filter_by(
        vulnerability_id=vulnerability_id,
        platform=platform,
        is_deleted=False
    ).first()
    if existing:
        raise ValidationError(
            f"Vulnerability already submitted to {platform.value if platform else 'this platform'}"
        )

    report = Report(**report_data)
    if not report.status:
        report.status = ReportStatus.DRAFT

    db.session.add(report)
    db.session.flush()  # assign report.id before Event.record

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.REPORT,
        entity_id=report.id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={
            "action": "report_created",
            "platform": platform.value if platform else None,
            "vulnerability_id": vulnerability_id,
        }
    )
    db.session.add(event)
    db.session.commit()
    return report


# ==============================================================================
# WRITE — SUBMIT (DRAFT → SUBMITTED)
# ==============================================================================

def submit_report(report_id: str, organization_id: str, actor_id: str,
                   submission_url: str = None, submission_id: str = None) -> Report:
    """
    Transitions a DRAFT report to SUBMITTED and records an Event.

    Usage:
        report = submit_report(
            report_id, org_id, actor_id=user.id,
            submission_url="https://hackerone.com/reports/12345"
        )
    """
    report = get_report(report_id, organization_id)
    if report is None:
        raise NotFoundError("Report not found")

    _assert_same_org(report, organization_id)

    if report.status != ReportStatus.DRAFT:
        raise ValidationError(
            f"Only DRAFT reports can be submitted (current: {report.status.value})"
        )

    if submission_url:
        report.submission_url = submission_url
    if submission_id:
        report.submission_id = submission_id

    report.mark_submitted()

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.REPORT,
        entity_id=report.id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={
            "action": "report_submitted",
            "platform": report.platform.value if report.platform else None,
            "submission_url": submission_url,
        }
    )
    db.session.add(event)
    db.session.commit()
    return report


# ==============================================================================
# WRITE — ACKNOWLEDGE
# ==============================================================================

def acknowledge_report(report_id: str, organization_id: str, actor_id: str,
                        vendor_response: str = None,
                        vendor_comment: str = None) -> Report:
    """
    Marks a SUBMITTED or TRIAGED report as acknowledged by the vendor.

    Usage:
        report = acknowledge_report(
            report_id, org_id, actor_id=user.id,
            vendor_response="We received your report and are investigating."
        )
    """
    report = get_report(report_id, organization_id)
    if report is None:
        raise NotFoundError("Report not found")

    _assert_same_org(report, organization_id)

    if report.status not in (ReportStatus.SUBMITTED, ReportStatus.TRIAGED):
        raise ValidationError(
            f"Cannot acknowledge a report with status '{report.status.value}'"
        )

    if vendor_response:
        report.vendor_response = vendor_response
    if vendor_comment:
        report.vendor_comment = vendor_comment

    report.mark_acknowledged()

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.REPORT,
        entity_id=report.id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={"action": "report_acknowledged"}
    )
    db.session.add(event)
    db.session.commit()
    return report


# ==============================================================================
# WRITE — RESOLVE (award bounty)
# ==============================================================================

def resolve_report(report_id: str, organization_id: str, actor_id: str,
                    bounty_amount: float = 0.0, bounty_currency: str = "USD",
                    vendor_response: str = None, swag_awarded: str = None) -> Report:
    """
    Marks a report as RESOLVED with bounty information, and syncs the
    cached Vulnerability.bounty_awarded/bounty_currency total.

    Usage:
        report = resolve_report(
            report_id, org_id, actor_id=user.id,
            bounty_amount=500.0, bounty_currency="USD"
        )
    """
    report = get_report(report_id, organization_id)
    if report is None:
        raise NotFoundError("Report not found")

    _assert_same_org(report, organization_id)

    if report.status in (ReportStatus.DRAFT, ReportStatus.RESOLVED):
        raise ValidationError(
            f"Cannot resolve a report with status '{report.status.value}'"
        )

    if bounty_amount < 0:
        raise ValidationError("bounty_amount cannot be negative")

    if vendor_response:
        report.vendor_response = vendor_response
    if swag_awarded:
        report.swag_awarded = swag_awarded

    report.mark_resolved(bounty_amount, bounty_currency)

    # Sync cached total on Vulnerability
    if bounty_amount > 0:
        vuln = Vulnerability.query.filter_by(
            id=report.vulnerability_id,
            organization_id=organization_id
        ).first()
        if vuln:
            vuln.bounty_awarded = bounty_amount
            vuln.bounty_currency = bounty_currency

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.REPORT,
        entity_id=report.id,
        event_type=EventType.VULN_BOUNTY_AWARDED,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={
            "action": "report_resolved",
            "bounty_amount": bounty_amount,
            "bounty_currency": bounty_currency,
        }
    )
    db.session.add(event)
    db.session.commit()
    return report


# ==============================================================================
# WRITE — SOFT DELETE
# ==============================================================================

def delete_report(report_id: str, organization_id: str, actor_id: str) -> Report:
    """
    Soft-deletes a report. Only DRAFT or REJECTED reports can be deleted —
    submitted/resolved reports are immutable financial/audit records.

    Usage:
        report = delete_report(report_id, org_id, actor_id=user.id)
    """
    report = get_report(report_id, organization_id)
    if report is None:
        raise NotFoundError("Report not found")

    _assert_same_org(report, organization_id)

    if report.status not in (ReportStatus.DRAFT, ReportStatus.REJECTED):
        raise ValidationError(
            f"Cannot delete a {report.status.value} report. "
            "Only DRAFT and REJECTED reports can be deleted."
        )

    report.soft_delete()

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.REPORT,
        entity_id=report.id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={
            "action": "report_deleted",
            "platform": report.platform.value if report.platform else None,
        }
    )
    db.session.add(event)
    db.session.commit()
    return report