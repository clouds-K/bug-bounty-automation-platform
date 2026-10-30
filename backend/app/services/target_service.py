"""
Target Service - Production SaaS Bug Bounty Platform

Mirrors the pattern established in vulnerability_service.py (4.4 - API
safety layer): routes call these functions, which handle org-scoping,
soft-delete-aware queries, validation, and Event recording in one place.

Design decisions (so future-you remembers why):
  - Validation lives here, not in routes/target.py. Both create_target()
    and update_target() need the same scan_url checks, so duplicating
    them in two route handlers was how they'd eventually drift apart.
  - Duplicate detection is keyed on scan_url (not domain). This is a
    deliberate behavior change from the old domain-based check: it means
    http://example.com and https://example.com/api are treated as two
    distinct targets. If you want domain-level dedup instead, that's a
    one-line change in _check_duplicate_scan_url — just be aware which
    one you're choosing.
  - Every function that writes wraps its commit in try/except and
    rolls back on failure, so a partial write (e.g. Event.record()
    throwing after the Target insert) never leaves a half-committed
    session behind.
  - Callers should catch ValueError and map it to a 400 response.
    CrossOrgViolation should map to 403. Anything else is a genuine
    500.
"""

from datetime import datetime
from urllib.parse import urlparse

from app import db
from app.models.target import Target
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.exceptions import CrossOrgViolation


# ==============================================================================
# FIELDS A CALLER IS ALLOWED TO UPDATE DIRECTLY VIA update_target()
# --------------------------------------------------------------------------
# Single source of truth. Do not duplicate this list in routes/target.py —
# import it from here if the route ever needs to reference it (e.g. for
# API docs / OpenAPI schema generation).
# ==============================================================================
ALLOWED_UPDATE_FIELDS = {
    "program_name",
    "program_url",
    "scope",
    "in_scope",
    "out_of_scope",
    "notes",
    "status",
    "asset_type",
    "is_verified",
    "scan_enabled",
    "scan_config",
}


# ==============================================================================
# INTERNAL HELPERS
# ==============================================================================

def _assert_same_org(target: Target, organization_id: str):
    if target.organization_id != organization_id:
        raise CrossOrgViolation(
            f"Target {target.id} does not belong to organization {organization_id}"
        )


def _normalize_scan_url(scan_url: str) -> str:
    """
    Normalizes a scan_url so trivial formatting differences don't create
    duplicate targets or break dedup:
        "HTTP://Example.com/"  ->  "http://example.com"
        " https://Foo.com/bar/" -> "https://foo.com/bar"

    Query strings are preserved as-is (case matters there). Does NOT
    validate the URL — call _validate_scan_url() separately.
    """
    if not scan_url:
        return scan_url

    scan_url = scan_url.strip()
    parsed = urlparse(scan_url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    normalized = f"{scheme}://{netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"

    return normalized


def _validate_scan_url(scan_url: str):
    """
    Raises ValueError with a user-facing message if scan_url is missing,
    malformed, or not http(s). Call this AFTER _normalize_scan_url().
    """
    if not scan_url:
        raise ValueError("scan_url is required")

    parsed = urlparse(scan_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("scan_url must start with http:// or https://")

    if not parsed.netloc:
        raise ValueError("Invalid scan_url")


def _check_duplicate_scan_url(organization_id: str, scan_url: str,
                               exclude_target_id: str = None):
    """
    Raises ValueError if another non-deleted target in this org already
    has this exact scan_url. Pass exclude_target_id when checking during
    an update, so the target isn't flagged as a duplicate of itself.
    """
    query = Target.query.filter_by(
        organization_id=organization_id,
        scan_url=scan_url,
        is_deleted=False
    )
    if exclude_target_id:
        query = query.filter(Target.id != exclude_target_id)

    existing = query.first()
    if existing:
        raise ValueError(
            f"Target with scan_url '{scan_url}' already exists in this organization"
        )


def _validate_rewards(data: dict, target: Target):
    """
    Returns (new_min, new_max) as floats, validated. Falls back to the
    target's current values for whichever key isn't present in data.
    Raises ValueError on bad input.
    """
    try:
        new_min = float(data.get("rewards_min", target.rewards_min))
        new_max = float(data.get("rewards_max", target.rewards_max))
    except (TypeError, ValueError):
        raise ValueError("rewards_min and rewards_max must be numbers")

    if new_min > new_max:
        raise ValueError("rewards_min cannot exceed rewards_max")

    return new_min, new_max


# ==============================================================================
# READ
# ==============================================================================

def get_target(target_id: str, organization_id: str) -> Target:
    """
    Org-scoped, non-deleted target lookup.

    Usage:
        target = get_target(target_id, current_user.organization_id)
        if target is None:
            abort(404)
    """
    return Target.query.filter_by(
        id=target_id,
        organization_id=organization_id,
        is_deleted=False
    ).first()


def list_targets(organization_id: str, status: str = None, platform: str = None):
    """Org-scoped, non-deleted target list, optionally filtered."""
    query = Target.query.filter_by(organization_id=organization_id, is_deleted=False)
    if status:
        query = query.filter_by(status=status)
    if platform:
        query = query.filter_by(platform=platform)
    return query


# ==============================================================================
# WRITE — CREATION
# ==============================================================================

def create_target(target_data: dict, actor_id: str,
                   source: EventSource = EventSource.USER) -> Target:
    """
    Creates a new Target scoped to target_data["organization_id"], and
    records a creation Event.

    target_data MUST include organization_id, user_id, scan_url.
    A "domain" key, if present, is IGNORED — domain is always derived
    server-side from scan_url via Target.sync_domain_from_scan_url(),
    so a caller can never desync the two.

    Raises:
        ValueError        — invalid/missing scan_url, or a duplicate
                             scan_url already exists in this org.
    """
    scan_url = _normalize_scan_url(target_data.get("scan_url", ""))
    _validate_scan_url(scan_url)

    organization_id = target_data["organization_id"]
    _check_duplicate_scan_url(organization_id, scan_url)

    # Don't trust a caller-supplied domain — always derive it ourselves.
    clean_data = dict(target_data)
    clean_data["scan_url"] = scan_url
    clean_data.pop("domain", None)

    try:
        target = Target(**clean_data)
        target.sync_domain_from_scan_url()

        db.session.add(target)
        db.session.flush()  # assigns target.id (UUID) before it's used in Event.record

        event = Event.record(
            organization_id=target.organization_id,
            entity_type=EntityType.TARGET,
            entity_id=target.id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=source,
            payload={
                "action": "created",
                "scan_url": target.scan_url,
                "domain": target.domain,
                "platform": target.platform,
            }
        )
        db.session.add(event)
        db.session.commit()
        return target

    except Exception:
        db.session.rollback()
        raise


# ==============================================================================
# WRITE — UPDATE
# ==============================================================================

def update_target(target_id: str, organization_id: str, data: dict,
                   actor_id: str) -> Target:
    """
    Updates an existing target. Handles scan_url validation/resync,
    field whitelisting, reward validation, and Event recording in one
    place — routes/target.py should just call this and translate the
    result/exception into an HTTP response.

    Returns:
        The updated Target, or None if no target matches
        (target_id, organization_id) / it's soft-deleted.
        If no recognized fields changed, returns the target unmodified
        without writing an Event (no-op updates shouldn't pollute the
        audit log).

    Raises:
        CrossOrgViolation  — target belongs to a different org.
        ValueError         — invalid scan_url, duplicate scan_url,
                              or invalid rewards.
    """
    target = get_target(target_id, organization_id)
    if target is None:
        return None

    _assert_same_org(target, organization_id)

    updated_fields = []

    try:
        # --- scan_url: validate, normalize, dedupe, resync domain ---
        if "scan_url" in data:
            new_scan_url = _normalize_scan_url(data["scan_url"])
            _validate_scan_url(new_scan_url)

            if new_scan_url != target.scan_url:
                _check_duplicate_scan_url(
                    organization_id, new_scan_url, exclude_target_id=target.id
                )
                target.scan_url = new_scan_url
                target.sync_domain_from_scan_url()
                updated_fields.append("scan_url")

        # --- whitelisted simple fields ---
        for field in ALLOWED_UPDATE_FIELDS:
            if field in data and getattr(target, field) != data[field]:
                setattr(target, field, data[field])
                updated_fields.append(field)

        # --- rewards (validated as a pair) ---
        if "rewards_min" in data or "rewards_max" in data:
            new_min, new_max = _validate_rewards(data, target)
            if new_min != target.rewards_min:
                target.rewards_min = new_min
                updated_fields.append("rewards_min")
            if new_max != target.rewards_max:
                target.rewards_max = new_max
                updated_fields.append("rewards_max")

        if not updated_fields:
            return target  # nothing actually changed — skip Event + commit

        target.updated_at = datetime.utcnow()

        event = Event.record(
            organization_id=organization_id,
            entity_type=EntityType.TARGET,
            entity_id=target.id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=EventSource.USER,
            payload={
                "action": "updated",
                "updated_fields": updated_fields,
            }
        )
        db.session.add(event)
        db.session.commit()
        return target

    except Exception:
        db.session.rollback()
        raise


# ==============================================================================
# WRITE — SOFT DELETE
# ==============================================================================

def delete_target(target_id: str, organization_id: str, actor_id: str) -> Target:
    """
    Soft-deletes a target. Does NOT cascade-delete vulnerabilities/exploits/
    reports -- those keep their target_id for historical reference.

    Idempotent: calling this on an already-deleted target just returns it
    without writing a second "deleted" Event.
    """
    target = get_target(target_id, organization_id)
    if target is None:
        return None

    _assert_same_org(target, organization_id)

    if target.is_deleted:
        return target  # already deleted — no-op, no duplicate Event

    try:
        target.soft_delete()

        event = Event.record(
            organization_id=organization_id,
            entity_type=EntityType.TARGET,
            entity_id=target.id,
            event_type=EventType.OTHER,
            actor_id=actor_id,
            source=EventSource.USER,
            payload={"action": "deleted"}
        )
        db.session.add(event)
        db.session.commit()
        return target

    except Exception:
        db.session.rollback()
        raise