"""
Bounty Service - Production SaaS Bug Bounty Platform

Mirrors the pattern established in vulnerability_service.py: routes call
these functions, which handle org-scoping, validation, Event recording, and
keeping Vulnerability's cached bounty_awarded/bounty_currency in sync once a
Bounty is actually paid.
"""

from app import db
from app.models.bounty import Bounty, BountyStatus, PaymentMethod
from app.models.vulnerability import Vulnerability
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.exceptions import CrossOrgViolation, NotFoundError, ValidationError


def _assert_same_org(bounty: Bounty, organization_id: str):
    if bounty.organization_id != organization_id:
        raise CrossOrgViolation(
            f"Bounty {bounty.id} does not belong to organization {organization_id}"
        )


# ==============================================================================
# READ
# ==============================================================================

def get_bounty(bounty_id: str, organization_id: str) -> Bounty:
    """Org-scoped, non-deleted bounty lookup."""
    return Bounty.query.filter_by(
        id=bounty_id, organization_id=organization_id, is_deleted=False
    ).first()


def list_bounties(organization_id: str, status: BountyStatus = None,
                   vulnerability_id: str = None, researcher_id: str = None):
    """Org-scoped, non-deleted bounty list, optionally filtered."""
    query = Bounty.query.filter_by(organization_id=organization_id, is_deleted=False)
    if status is not None:
        query = query.filter_by(status=status)
    if vulnerability_id is not None:
        query = query.filter_by(vulnerability_id=vulnerability_id)
    if researcher_id is not None:
        query = query.filter_by(researcher_id=researcher_id)
    return query


# ==============================================================================
# WRITE — PROPOSE
# ==============================================================================

SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP"}
MAX_BOUNTY_AMOUNT = 100_000.0


def propose_bounty(organization_id: str, vulnerability_id: str, amount: float,
                    currency: str, actor_id: str, is_bonus: bool = False,
                    bonus_reason: str = None) -> Bounty:
    """
    Proposes a new bounty for a vulnerability (status=PROPOSED). The
    researcher is taken from Vulnerability.user_id (the original reporter).

    Permission note: any authenticated organization member may propose a
    bounty (e.g. a triager suggesting an amount for review) -- the User
    model currently only has roles "user" / "admin" / "superadmin", with no
    dedicated "triager" role, so proposing is intentionally open to all org
    members. Approval/rejection/payment remain admin-only (enforced in
    bounty_routes.py). If a more granular "triager" role is added to User
    later, restrict proposal there too.

    Usage:
        bounty = propose_bounty(
            org_id, vuln_id, amount=500.0, currency="USD", actor_id=triager.id
        )
    """
    if amount <= 0:
        raise ValidationError("Bounty amount must be greater than zero")
    if amount > MAX_BOUNTY_AMOUNT:
        raise ValidationError(f"Bounty amount cannot exceed {MAX_BOUNTY_AMOUNT}")

    currency = (currency or "USD").upper()
    if currency not in SUPPORTED_CURRENCIES:
        raise ValidationError(
            f"Currency '{currency}' is not supported. Supported: {', '.join(sorted(SUPPORTED_CURRENCIES))}"
        )

    vuln = Vulnerability.active(id=vulnerability_id, organization_id=organization_id).first()
    if vuln is None:
        raise NotFoundError("Vulnerability not found")

    bounty = Bounty(
        organization_id=organization_id,
        vulnerability_id=vulnerability_id,
        researcher_id=vuln.user_id,
        amount=amount,
        currency=currency,
        is_bonus=is_bonus,
        bonus_reason=bonus_reason,
        status=BountyStatus.PROPOSED,
    )
    db.session.add(bounty)
    db.session.flush()  # assign bounty.id before using it in Event.record

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.VULNERABILITY,
        entity_id=vuln.id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={"action": "bounty_proposed", "bounty_id": bounty.id,
                 "amount": amount, "currency": currency}
    )
    db.session.add(event)
    db.session.commit()
    return bounty


# ==============================================================================
# WRITE — APPROVE / REJECT
# ==============================================================================

def approve_bounty(bounty_id: str, organization_id: str, actor_id: str,
                    notes: str = None) -> Bounty:
    """Approves a PROPOSED bounty."""
    bounty = get_bounty(bounty_id, organization_id)
    if bounty is None:
        raise NotFoundError("Bounty not found")
    _assert_same_org(bounty, organization_id)

    bounty.approve(approved_by_id=actor_id, notes=notes)

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.VULNERABILITY,
        entity_id=bounty.vulnerability_id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={"action": "bounty_approved", "bounty_id": bounty.id}
    )
    db.session.add(event)
    db.session.commit()
    return bounty


def reject_bounty(bounty_id: str, organization_id: str, actor_id: str, reason: str) -> Bounty:
    """Rejects a PROPOSED bounty."""
    bounty = get_bounty(bounty_id, organization_id)
    if bounty is None:
        raise NotFoundError("Bounty not found")
    _assert_same_org(bounty, organization_id)

    bounty.reject(rejected_by_id=actor_id, reason=reason)

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.VULNERABILITY,
        entity_id=bounty.vulnerability_id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={"action": "bounty_rejected", "bounty_id": bounty.id, "reason": reason}
    )
    db.session.add(event)
    db.session.commit()
    return bounty


# ==============================================================================
# WRITE — MARK PAID
# --------------------------------------------------------------------------
# This is the point where Vulnerability's cached bounty_awarded/
# bounty_currency are updated, so dashboards reading Vulnerability directly
# (without joining Bounty) still show the correct total.
# ==============================================================================

def mark_bounty_paid(bounty_id: str, organization_id: str, actor_id: str,
                      payment_method: PaymentMethod,
                      stripe_payment_intent_id: str = None) -> Bounty:
    """
    Marks an APPROVED bounty as PAID and syncs Vulnerability's cached total.

    Usage:
        bounty = mark_bounty_paid(
            bounty_id, org_id, actor_id=admin.id,
            payment_method=PaymentMethod.STRIPE,
            stripe_payment_intent_id="pi_..."
        )
    """
    bounty = get_bounty(bounty_id, organization_id)
    if bounty is None:
        raise NotFoundError("Bounty not found")
    _assert_same_org(bounty, organization_id)

    bounty.mark_paid(
        paid_by_id=actor_id,
        payment_method=payment_method,
        stripe_payment_intent_id=stripe_payment_intent_id,
    )

    # Sync the cached total on Vulnerability (sum of all PAID bounties for it)
    vuln = Vulnerability.query.filter_by(id=bounty.vulnerability_id).first()
    if vuln:
        total_paid = db.session.query(
            db.func.coalesce(db.func.sum(Bounty.amount), 0.0)
        ).filter_by(
            vulnerability_id=vuln.id,
            organization_id=organization_id,
            status=BountyStatus.PAID
        ).scalar()
        vuln.bounty_awarded = float(total_paid)
        vuln.bounty_currency = bounty.currency

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.VULNERABILITY,
        entity_id=bounty.vulnerability_id,
        event_type=EventType.VULN_BOUNTY_AWARDED,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={
            "action": "bounty_paid",
            "bounty_id": bounty.id,
            "amount": bounty.amount,
            "currency": bounty.currency,
            "payment_method": payment_method.value,
        }
    )
    db.session.add(event)
    db.session.commit()
    return bounty


# ==============================================================================
# WRITE — DISPUTE
# ==============================================================================

def dispute_bounty(bounty_id: str, organization_id: str, actor_id: str, reason: str) -> Bounty:
    """Flags an APPROVED or PAID bounty as disputed."""
    bounty = get_bounty(bounty_id, organization_id)
    if bounty is None:
        raise NotFoundError("Bounty not found")
    _assert_same_org(bounty, organization_id)

    bounty.open_dispute(reason)

    event = Event.record(
        organization_id=organization_id,
        entity_type=EntityType.VULNERABILITY,
        entity_id=bounty.vulnerability_id,
        event_type=EventType.OTHER,
        actor_id=actor_id,
        source=EventSource.USER,
        payload={"action": "bounty_disputed", "bounty_id": bounty.id, "reason": reason}
    )
    db.session.add(event)
    db.session.commit()
    return bounty