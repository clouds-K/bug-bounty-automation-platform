"""
Modèle Report - Production SaaS Bug Bounty Platform
Représente un rapport de vulnérabilité soumis à une plateforme ou un programme
"""

from app import db
from sqlalchemy.sql import func
import uuid
from enum import Enum


# ==========================
# ENUMS
# ==========================

class ReportStatus(Enum):
    """Workflow de soumission d'un rapport"""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class ReportPlatform(Enum):
    """Plateformes bug bounty"""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    YESWEHACK = "yeswehack"
    INTIGRITI = "intigriti"
    DIRECT = "direct"
    EMAIL = "email"


# ==========================
# MODEL
# ==========================

class Report(db.Model):
    """
    Report model - tracks vulnerability submissions to vendors/programs
    """

    __tablename__ = "reports"

    # ==========================================================================
    # COMPOSITE INDEXES — Multi-Tenant Performance
    # --------------------------------------------------------------------------
    # idx_report_org_status : "all draft/submitted reports in org X" (dashboard)
    # idx_report_org_vuln    : "all reports for vuln X in org Y"
    # ==========================================================================
    __table_args__ = (
        db.Index("idx_report_org_status", "organization_id", "status"),
        db.Index("idx_report_org_vuln",   "organization_id", "vulnerability_id"),
    )

    # ==========================
    # IDENTIFIERS
    # ==========================

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # ==========================================================================
    # MULTI-TENANT — organization_id
    # --------------------------------------------------------------------------
    # NOTE (consistency fix): like Target/Exploit, Report previously had no
    # direct organization_id. Added for consistency with the rest of the
    # schema and to allow org-scoped queries without joining through user or
    # vulnerability. nullable=False, ondelete="RESTRICT" — soft-delete-only
    # pattern, same as everywhere else.
    # ==========================================================================
    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    organization = db.relationship(
        "Organization",
        back_populates="reports"
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    vulnerability_id = db.Column(
        db.String(36),
        db.ForeignKey("vulnerabilities.id"),
        nullable=False,
        index=True
    )

    target_id = db.Column(
        db.String(36),
        db.ForeignKey("targets.id"),
        nullable=False,
        index=True
    )

    # ==========================================================================
    # RELATIONSHIPS
    # --------------------------------------------------------------------------
    # "user" : FIX (same issue as Exploit<->User). user.py declares
    #   reports = db.relationship("Report", backref="user", lazy=True)
    # so this side must NOT also declare backref="reports" — two competing
    # declarations of Report.user / User.reports would crash at mapper
    # configuration time. user.py is the side that owns the backref here
    # (back_populates is not needed if only ONE side uses backref — keep
    # user.py's `reports = db.relationship("Report", backref="user", ...)`
    # AS IS, and do NOT declare `user = db.relationship(...)` here).
    #
    # "vulnerability" / "target" : Vulnerability and Target do NOT declare
    # their own "reports" attribute, so backref here is the sole owner —
    # no conflict.
    # ==========================================================================
    vulnerability = db.relationship("Vulnerability", backref="reports")
    target = db.relationship("Target", backref="reports")

    # ==========================
    # CORE INFO
    # ==========================

    title = db.Column(
        db.String(255),
        nullable=False,
        index=True
    )

    description = db.Column(db.Text, nullable=False)
    summary = db.Column(db.Text)

    # ==========================
    # PLATFORM TRACKING
    # ==========================

    platform = db.Column(
        db.Enum(ReportPlatform),
        nullable=False,
        index=True
    )

    status = db.Column(
        db.Enum(ReportStatus),
        default=ReportStatus.DRAFT,
        nullable=False,
        index=True
    )

    submission_url = db.Column(db.String(500))

    submission_id = db.Column(
        db.String(255),
        unique=True,
        index=True
    )
    # ex: "H1-123456"

    # ==========================
    # TECHNICAL WRITEUP
    # ==========================

    steps_to_reproduce = db.Column(db.Text, nullable=False)

    impact = db.Column(db.Text, nullable=False)
    remediation = db.Column(db.Text)

    # ==========================
    # EVIDENCE
    # ==========================

    payload = db.Column(db.JSON)
    screenshot_urls = db.Column(db.JSON)
    video_url = db.Column(db.String(500))
    poc_url = db.Column(db.String(500))

    # ==========================
    # SEVERITY / SCORING
    # ==========================

    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(255))

    severity_level = db.Column(
        db.Integer
    )
    # 1-5 internal scale (or map to CVSS)

    # ==========================
    # VENDOR INTERACTION
    # ==========================

    vendor_response = db.Column(db.Text)
    vendor_comment = db.Column(db.Text)

    is_acknowledged = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    acknowledged_at = db.Column(db.DateTime(timezone=True))

    # ==========================
    # RESOLUTION
    # ==========================

    is_resolved = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    resolved_at = db.Column(db.DateTime(timezone=True))

    bounty_amount = db.Column(
        db.Float,
        default=0.0
    )

    bounty_currency = db.Column(
        db.String(10),
        default="USD"
    )

    swag_awarded = db.Column(db.Text)

    # ==========================================================================
    # SOFT DELETE
    # --------------------------------------------------------------------------
    # Same pattern as Organization/Vulnerability/Target/Exploit.
    # ==========================================================================
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

    # ==========================
    # INTERNAL METADATA
    # ==========================

    internal_notes = db.Column(db.Text)

    tags = db.Column(db.JSON)
    # ["critical", "duplicate-risk", "first-blood"]

    # ==========================
    # AUDIT
    # ==========================

    submitted_at = db.Column(db.DateTime(timezone=True))

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
    # ORG SAFETY
    # ==========================================================================

    def belongs_to_org(self, org_id: str) -> bool:
        """
        Vérifie que ce report appartient bien à l'organisation donnée.

        Usage côté service AVANT toute lecture/écriture :
            if not report.belongs_to_org(current_user.organization_id):
                abort(404)
        """
        return self.organization_id == org_id

    # ==========================================================================
    # SOFT DELETE
    # ==========================================================================

    def soft_delete(self):
        """Désactive le report sans le supprimer physiquement."""
        from datetime import datetime
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()

    # ==========================================================================
    # WORKFLOW HELPERS
    # ==========================================================================

    def mark_submitted(self):
        """Transition DRAFT -> SUBMITTED, set submitted_at."""
        from datetime import datetime
        self.status = ReportStatus.SUBMITTED
        self.submitted_at = datetime.utcnow()

    def mark_acknowledged(self):
        """Transition -> ACKNOWLEDGED, set acknowledged_at + is_acknowledged."""
        from datetime import datetime
        self.status = ReportStatus.ACKNOWLEDGED
        self.is_acknowledged = True
        self.acknowledged_at = datetime.utcnow()

    def mark_resolved(self, bounty_amount: float = None, bounty_currency: str = "USD"):
        """Transition -> RESOLVED, set resolved_at + optional bounty."""
        from datetime import datetime
        self.status = ReportStatus.RESOLVED
        self.is_resolved = True
        self.resolved_at = datetime.utcnow()
        if bounty_amount is not None:
            if bounty_amount < 0:
                raise ValueError("Bounty amount cannot be negative")
            self.bounty_amount = bounty_amount
            self.bounty_currency = bounty_currency

    # ==========================
    # SERIALIZATION
    # ==========================

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "user_id": self.user_id,
            "vulnerability_id": self.vulnerability_id,
            "target_id": self.target_id,

            "title": self.title,
            "description": self.description,
            "summary": self.summary,

            "platform": self.platform.value if self.platform else None,
            "status": self.status.value if self.status else None,

            "submission_url": self.submission_url,
            "submission_id": self.submission_id,

            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
            "remediation": self.remediation,

            "payload": self.payload,
            "screenshot_urls": self.screenshot_urls,
            "video_url": self.video_url,
            "poc_url": self.poc_url,

            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity_level": self.severity_level,

            "vendor_response": self.vendor_response,
            "vendor_comment": self.vendor_comment,

            "is_acknowledged": self.is_acknowledged,
            "acknowledged_at": (
                self.acknowledged_at.isoformat()
                if self.acknowledged_at else None
            ),

            "is_resolved": self.is_resolved,
            "resolved_at": (
                self.resolved_at.isoformat()
                if self.resolved_at else None
            ),

            "bounty_amount": self.bounty_amount,
            "bounty_currency": self.bounty_currency,
            "swag_awarded": self.swag_awarded,

            "is_deleted": self.is_deleted,
            "deleted_at": (
                self.deleted_at.isoformat() if self.deleted_at else None
            ),

            "internal_notes": self.internal_notes,
            "tags": self.tags,

            "submitted_at": (
                self.submitted_at.isoformat()
                if self.submitted_at else None
            ),

            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def to_simple_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "platform": self.platform.value if self.platform else None,
            "status": self.status.value if self.status else None,
            "severity_level": self.severity_level,
            "bounty_amount": self.bounty_amount,
            "is_resolved": self.is_resolved,
            "created_at": self.created_at.isoformat()
        }

    def __repr__(self) -> str:
        return f"<Report {self.title} | org={self.organization_id}>"