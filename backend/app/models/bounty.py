"""
Modèle Bounty - Production SaaS Bug Bounty Platform

==============================================================================
PURPOSE
==============================================================================
Vulnerability.bounty_awarded / bounty_currency are kept as a denormalized
"current total" cache for quick display (same pattern as
Target.vuln_count_total caching Vulnerability counts). They are NOT removed.

Bounty is the actual workflow + audit model: a vulnerability can have
multiple Bounty rows over its lifetime (e.g. a bonus added later, a dispute
resulting in a corrected amount), each with its own approval chain and
Stripe payment trail. Vulnerability.award_bounty() should be called AFTER
a Bounty reaches PAID status, to keep the cached total in sync — see
bounty_service.py for the orchestration.
==============================================================================
"""

from app import db
from sqlalchemy.sql import func
from datetime import datetime
import uuid
from enum import Enum


# ==============================================================================
# ENUMS
# ==============================================================================

class BountyStatus(Enum):
    PROPOSED  = "proposed"   # researcher/triager suggests an amount
    APPROVED  = "approved"   # org admin approved the amount
    PAID      = "paid"       # payment sent (Stripe transfer or manual)
    REJECTED  = "rejected"   # proposal declined
    DISPUTED  = "disputed"   # amount contested after approval/payment


class PaymentMethod(Enum):
    STRIPE         = "stripe"
    BANK_TRANSFER  = "bank_transfer"
    MANUAL         = "manual"
    SWAG           = "swag"   # non-monetary reward (t-shirt, credits, etc.)


# ==============================================================================
# MODEL
# ==============================================================================
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MULTI-TENANT SAFETY RULE                                                  ║
# ║  ALL QUERIES MUST FILTER BY organization_id                                ║
# ║                                                                             ║
# ║  ✅  Bounty.query.filter_by(organization_id=org_id, ...)                   ║
# ║  ❌  Bounty.query.filter_by(vulnerability_id=x)  ← DATA LEAK               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# ==============================================================================
class Bounty(db.Model):
    __tablename__ = "bounties"

    # ==========================================================================
    # COMPOSITE INDEXES — Multi-Tenant Performance
    # --------------------------------------------------------------------------
    # idx_bounty_org_vuln    : "all bounties for vuln X in org Y" (history)
    # idx_bounty_org_status  : "all PROPOSED/APPROVED bounties in org Y"
    #                          (approval queue, payout queue)
    # ==========================================================================
    __table_args__ = (
        db.Index("idx_bounty_org_vuln",   "organization_id", "vulnerability_id"),
        db.Index("idx_bounty_org_status", "organization_id", "status"),
    )

    # ==========================================================================
    # IDENTIFIERS
    # ==========================================================================
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    organization = db.relationship(
        "Organization",
        backref=db.backref("bounties", lazy="select")
    )

    vulnerability_id = db.Column(
        db.String(36),
        db.ForeignKey("vulnerabilities.id"),
        nullable=False,
        index=True
    )

    vulnerability = db.relationship("Vulnerability", backref="bounties")

    # ==========================================================================
    # PARTIES — researcher (recipient) vs approver (org side)
    # --------------------------------------------------------------------------
    # researcher_id : the user being paid (typically Vulnerability.user_id,
    #                 but tracked explicitly here in case of reassignment).
    # approved_by_id: org admin/triager who approved the amount. Nullable
    #                 until approval happens.
    # ==========================================================================
    researcher_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    researcher = db.relationship("User", foreign_keys=[researcher_id])

    approved_by_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=True
    )

    approver = db.relationship("User", foreign_keys=[approved_by_id])

    # ==========================================================================
    # AMOUNT
    # ==========================================================================
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default="USD", nullable=False)

    is_bonus = db.Column(db.Boolean, default=False, nullable=False)
    bonus_reason = db.Column(db.Text, nullable=True)
    # e.g. "First valid submission", "Critical severity bonus"

    # ==========================================================================
    # WORKFLOW STATUS
    # ==========================================================================
    status = db.Column(
        db.Enum(BountyStatus),
        default=BountyStatus.PROPOSED,
        nullable=False,
        index=True
    )

    approval_notes = db.Column(db.Text, nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)

    rejection_reason = db.Column(db.Text, nullable=True)

    # ==========================================================================
    # PAYMENT
    # ==========================================================================
    payment_method = db.Column(db.Enum(PaymentMethod), nullable=True)

    # Stripe Connect transfer id (paying OUT to the researcher) — distinct
    # from Organization.stripe_subscription_id, which is the org's own
    # inbound SaaS subscription billing.
    stripe_payment_intent_id = db.Column(db.String(100), unique=True, nullable=True)

    paid_at = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # DISPUTE
    # ==========================================================================
    is_disputed = db.Column(db.Boolean, default=False, nullable=False)
    dispute_reason = db.Column(db.Text, nullable=True)
    disputed_at = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # SOFT DELETE
    # --------------------------------------------------------------------------
    # Same pattern as Organization/Vulnerability/Target/Exploit/Report. Use
    # ONLY to correct a data-entry error (e.g. proposed against the wrong
    # vulnerability). For a normal "this bounty shouldn't be paid" decision,
    # use reject() instead -- that preserves the proposal in the audit trail
    # with a reason, which soft-delete does not.
    # ==========================================================================
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # AUDIT TRAIL — same pattern as Vulnerability.status_history
    # ==========================================================================
    status_history = db.Column(db.JSON, default=list, nullable=False)

    # ==========================================================================
    # TIMESTAMPS
    # ==========================================================================
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    # ==========================================================================
    # __init__
    # ==========================================================================
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.status_history:
            self.status_history = []

    # ==========================================================================
    # WORKFLOW METHODS
    # --------------------------------------------------------------------------
    # Same audit pattern as Vulnerability.log_status_change(): every
    # transition is appended to status_history with actor + timestamp.
    # ==========================================================================

    def _log_transition(self, new_status: BountyStatus, changed_by_id: str = None):
        self.status_history = self.status_history + [{
            "from": self.status.value if self.status else None,
            "to": new_status.value,
            "at": datetime.utcnow().isoformat(),
            "changed_by_id": changed_by_id,
        }]
        self.status = new_status

    def approve(self, approved_by_id: str, notes: str = None):
        """
        Transition PROPOSED -> APPROVED.

        Usage:
            bounty.approve(approved_by_id=admin.id, notes="Confirmed critical severity")
            db.session.commit()
        """
        if self.status != BountyStatus.PROPOSED:
            raise ValueError(f"Cannot approve a bounty with status '{self.status.value}'")
        self.approved_by_id = approved_by_id
        self.approval_notes = notes
        self.approved_at = datetime.utcnow()
        self._log_transition(BountyStatus.APPROVED, changed_by_id=approved_by_id)

    def reject(self, rejected_by_id: str, reason: str):
        """Transition PROPOSED -> REJECTED."""
        if self.status != BountyStatus.PROPOSED:
            raise ValueError(f"Cannot reject a bounty with status '{self.status.value}'")
        self.rejection_reason = reason
        self._log_transition(BountyStatus.REJECTED, changed_by_id=rejected_by_id)

    def mark_paid(self, paid_by_id: str, payment_method: PaymentMethod,
                  stripe_payment_intent_id: str = None):
        """
        Transition APPROVED -> PAID.

        Usage:
            bounty.mark_paid(
                paid_by_id=admin.id,
                payment_method=PaymentMethod.STRIPE,
                stripe_payment_intent_id="pi_..."
            )
            db.session.commit()
        """
        if self.status != BountyStatus.APPROVED:
            raise ValueError(f"Cannot mark paid a bounty with status '{self.status.value}'")
        self.payment_method = payment_method
        self.stripe_payment_intent_id = stripe_payment_intent_id
        self.paid_at = datetime.utcnow()
        self._log_transition(BountyStatus.PAID, changed_by_id=paid_by_id)

    def open_dispute(self, reason: str):
        """Mark a PAID or APPROVED bounty as disputed (does not change status, just flags it)."""
        if self.status not in (BountyStatus.APPROVED, BountyStatus.PAID):
            raise ValueError(f"Cannot dispute a bounty with status '{self.status.value}'")
        self.is_disputed = True
        self.dispute_reason = reason
        self.disputed_at = datetime.utcnow()

    def soft_delete(self):
        """
        Soft-deletes this bounty record. Use ONLY for data-entry corrections
        (e.g. proposed against the wrong vulnerability) -- for a normal
        "this shouldn't be paid" decision, use reject() instead, which keeps
        the record visible in the audit trail with a documented reason.
        """
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()

    # ==========================================================================
    # SERIALIZATION
    # ==========================================================================

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "vulnerability_id": self.vulnerability_id,
            "researcher_id": self.researcher_id,
            "approved_by_id": self.approved_by_id,

            "amount": self.amount,
            "currency": self.currency,
            "is_bonus": self.is_bonus,
            "bonus_reason": self.bonus_reason,

            "status": self.status.value if self.status else None,
            "approval_notes": self.approval_notes,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "rejection_reason": self.rejection_reason,

            "payment_method": self.payment_method.value if self.payment_method else None,
            "stripe_payment_intent_id": self.stripe_payment_intent_id,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,

            "is_disputed": self.is_disputed,
            "dispute_reason": self.dispute_reason,
            "disputed_at": self.disputed_at.isoformat() if self.disputed_at else None,

            "is_deleted": self.is_deleted,
            "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,

            "status_history": self.status_history,

            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def to_simple_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "researcher_id": self.researcher_id,
            "amount": self.amount,
            "currency": self.currency,
            "status": self.status.value if self.status else None,
            "is_bonus": self.is_bonus,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<Bounty {self.amount} {self.currency} | {self.status.value if self.status else '?'} | org={self.organization_id}>"