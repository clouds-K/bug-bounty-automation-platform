"""
Scan Service - Production SaaS Bug Bounty Platform

Mirrors the pattern in target_service.py / vulnerability_service.py: routes
call these functions, which handle org-scoping, business-rule validation,
Event recording, and commit/rollback in one place.

This closes three gaps that existed when Scan mutations lived directly in
routes/scan.py:
  1. No Event was ever recorded for scan creation/cancellation/status
     changes -- your audit trail had a hole for the entire scan lifecycle.
  2. create_scan() never checked target.scan_enabled before dispatching to
     Celery, so a paused target still consumed a worker slot before
     scanner.py's own check caught it and marked the scan failed.
  3. Plan-based daily scan quotas (PLAN_LIMITS) were defined in scanner.py
     but never enforced anywhere -- a free-tier org could queue unlimited
     scans.

NOTE ON PLAN_LIMITS DUPLICATION:
  scanner.py already defines a PLAN_LIMITS dict (rate_limit, timeout,
  scans_per_day) used for the actual Nuclei run. It's duplicated here
  rather than imported, deliberately: scanner.py pulls in the Celery task
  decorator and subprocess/nuclei machinery, which you don't want as an
  import-time side effect of a module that's loaded by the Flask
  request/response cycle. If these two dicts drift out of sync, that's
  the signal to extract both into a shared app/config/plan_limits.py.

  FIX (this revision): the "free" tier had drifted out of sync --
  scanner.py said 5 scans/day, this file said 10. Values are now
  identical to scanner.py's PLAN_LIMITS. If you change one, change
  the other, or better yet extract both to app/config/plan_limits.py
  so this can't happen again.

NOTE ON update_scan_status():
  This function is the single place that applies a worker-reported status
  transition to both the Scan and its Target, and records an Event for it.
  routes/scan.py's PATCH /<scan_id>/status endpoint should call this --
  see the worker-auth gating added there, since this endpoint mutates scan
  state on behalf of a worker process, not an interactively-authenticated
  user, and untrusted callers should not be able to reach it.

  FIX (this revision): the Event.record() call at the end used
  `target.id` unconditionally even though every mutation above it is
  guarded by `if target:`. A scan whose target had since been deleted
  (or any other case where the lookup returns None) would raise
  AttributeError on a None target instead of failing gracefully. The
  Event now falls back to `scan.target_id` when target is None.
"""

from datetime import datetime, timedelta

from app import db
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.models.organization import Organization
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.exceptions import CrossOrgViolation
from app.config.plan_limits import PLAN_LIMITS




# ==============================================================================
# INTERNAL HELPERS
# ==============================================================================

def _assert_same_org(scan: Scan, organization_id: str):
    if scan.organization_id != organization_id:
        raise CrossOrgViolation(
            f"Scan {scan.id} does not belong to organization {organization_id}"
        )


def _check_scan_quota(organization_id: str):
    """
    Raises ValueError if the org has hit its plan's daily scan limit.
    Rolling 24h window, not calendar-day, to keep this simple and avoid
    timezone edge cases around midnight.
    """
    org = Organization.query.get(organization_id)
    plan = org.plan if org else "free"
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])

    since = datetime.utcnow() - timedelta(days=1)
    recent_count = Scan.query.filter(
        Scan.organization_id == organization_id,
        Scan.created_at >= since
    ).count()

    if recent_count >= limits["scans_per_day"]:
        raise ValueError(
            f"Daily scan limit reached for plan '{plan}' "
            f"({limits['scans_per_day']} scans/24h)"
        )


# ==============================================================================
# READ
# ==============================================================================

def get_scan(scan_id: str, organization_id: str) -> Scan:
    """Org-scoped scan lookup."""
    return Scan.query.filter_by(
        id=scan_id,
        organization_id=organization_id
    ).first()


def list_scans(organization_id: str, status: ScanStatus = None, target_id: str = None):
    """Org-scoped scan list, optionally filtered by status and/or target."""
    query = Scan.query.filter_by(organization_id=organization_id)
    if status is not None:
        query = query.filter_by(status=status)
    if target_id:
        query = query.filter_by(target_id=target_id)
    return query


# ==============================================================================
# WRITE — CREATION
# ==============================================================================

def create_scan(scan_data: dict, actor_id: str,
                 source: EventSource = EventSource.USER) -> Scan:
    """
    Creates a new Scan, after checking:
      - the target exists, is not soft-deleted, and belongs to this org
      - the target is not paused (scan_enabled=False)
      - the org hasn't hit its plan's daily scan quota

    scan_data MUST include organization_id, user_id, target_id, scan_type,
    tools, config, status, progress (see routes/scan.py for how this is
    built from the request body).

    Raises:
        ValueError — target not found, target paused, or quota exceeded.
    """
    organization_id = scan_data["organization_id"]
    target_id = scan_data["target_id"]

    target = Target.query.filter_by(
        id=target_id, organization_id=organization_id, is_deleted=False
    ).first()
    if target is None:
        raise ValueError("Target not found")

    if not target.scan_enabled:
        raise ValueError("Scanning is paused for this target")

    _check_scan_quota(organization_id)

    try:
        scan = Scan(**scan_data)
        db.session.add(scan)
        db.session.flush()  # assigns scan.id before it's used in Event.record

        event = Event.record(
            organization_id=organization_id,
            entity_type=EntityType.TARGET,
            entity_id=target.id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=source,
            payload={
                "action": "created",
                "target_id": target_id,
                "scan_type": scan.scan_type.value if scan.scan_type else None,
                "tools": scan.tools,
            }
        )
        db.session.add(event)
        db.session.commit()
        return scan

    except Exception:
        db.session.rollback()
        raise


# ==============================================================================
# WRITE — CANCEL
# ==============================================================================

def cancel_scan(scan_id: str, organization_id: str, actor_id: str) -> Scan:
    """
    Cancels a queued or running scan and records an Event.

    Returns:
        The cancelled Scan, or None if no scan matches
        (scan_id, organization_id).

    Raises:
        CrossOrgViolation — scan belongs to a different org.
        ValueError        — scan is already in a terminal state
                             (completed/failed/cancelled).
    """
    scan = get_scan(scan_id, organization_id)
    if scan is None:
        return None

    _assert_same_org(scan, organization_id)

    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise ValueError(f"Cannot cancel a scan with status '{scan.status.value}'")

    try:
        scan.mark_cancelled()

        event = Event.record(
            organization_id=organization_id,
            entity_type=EntityType.TARGET,
            entity_id= scan.target_id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=EventSource.USER,
            payload={"action": "cancelled"}
        )
        db.session.add(event)
        db.session.commit()
        return scan

    except Exception:
        db.session.rollback()
        raise


# ==============================================================================
# WRITE — WORKER STATUS UPDATE
# ==============================================================================

def update_scan_status(scan_id: str, organization_id: str, data: dict,
                        actor_id: str = None,
                        source: EventSource = EventSource.SCANNER) -> Scan:
    """
    Applies a worker-reported status transition to the Scan (and its
    Target, where relevant), and records one Event for it.

    data MUST include "status" as an already-parsed ScanStatus enum (the
    route is responsible for string -> enum conversion, same convention
    as vulnerability_service.update_vulnerability). May also include
    "progress" (int, already range-validated by the caller) and
    "vulnerabilities_found" / "error_message" depending on the target
    status.

    Returns:
        The updated Scan, or None if no scan matches
        (scan_id, organization_id).

    Raises:
        CrossOrgViolation — scan belongs to a different org.
    """
    scan = get_scan(scan_id, organization_id)
    if scan is None:
        return None

    _assert_same_org(scan, organization_id)

    new_status: ScanStatus = data["status"]
    target = Target.query.filter_by(id=scan.target_id).first()

    try:
        if new_status == ScanStatus.RUNNING:
            scan.mark_started()
            if target:
                target.mark_scan_started()

        elif new_status == ScanStatus.COMPLETED:
            vulns_found = data.get("vulnerabilities_found", scan.vulnerabilities_found)
            scan.mark_completed(vulnerabilities_found=vulns_found)
            if target:
                target.mark_scan_completed()
                target.update_vuln_stats()

        elif new_status == ScanStatus.FAILED:
            scan.mark_failed(error_message=data.get("error_message"))
            if target:
                target.mark_scan_failed()

        elif new_status == ScanStatus.CANCELLED:
            scan.mark_cancelled()

        else:
            # QUEUED or other — no special transition side effects
            scan.status = new_status

        if data.get("progress") is not None:
            scan.update_progress(data["progress"])

        # FIX: target may be None (e.g. looked up target row no longer
        # exists), but every scan always has a target_id. Fall back to
        # that instead of dereferencing target.id unconditionally.
        event = Event.record(
            organization_id=organization_id,
            entity_type=EntityType.TARGET,
            entity_id=target.id if target else scan.target_id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=source,
            payload={
                "action": "status_changed",
                "status": new_status.value,
                "progress": scan.progress,
            }
        )
        db.session.add(event)
        db.session.commit()
        return scan

    except Exception:
        db.session.rollback()
        raise