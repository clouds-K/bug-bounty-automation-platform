"""
Modèle Scan - Production SaaS Bug Bounty Platform
Représente une exécution de scan automatisé sur un Target
"""

from app import db
from sqlalchemy.sql import func
from datetime import datetime
import uuid
from enum import Enum


# ==============================================================================
# ENUMS
# ==============================================================================

class ScanStatus(Enum):
    QUEUED     = "queued"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"


class ScanType(Enum):
    FULL    = "full"
    QUICK   = "quick"
    CUSTOM  = "custom"


# ==============================================================================
# MODEL
# ==============================================================================
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MULTI-TENANT SAFETY RULE                                                  ║
# ║  ALL QUERIES MUST FILTER BY organization_id                                ║
# ║                                                                             ║
# ║  ✅  Scan.query.filter_by(organization_id=org_id, ...)                     ║
# ║  ❌  Scan.query.filter_by(target_id=x)  ← DATA LEAK                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# ==============================================================================
class Scan(db.Model):
    __tablename__ = "scans"

    # ==========================================================================
    # COMPOSITE INDEXES — Multi-Tenant Performance
    # --------------------------------------------------------------------------
    # idx_scan_org_target  : "scan history for target X in org Y"
    # idx_scan_org_status  : "all running/queued scans in org Y" (worker queue,
    #                         plan quota enforcement via PLAN_LIMITS["scans"])
    # ==========================================================================
    __table_args__ = (
        db.Index("idx_scan_org_target", "organization_id", "target_id"),
        db.Index("idx_scan_org_status", "organization_id", "status"),
    )

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # ==========================================================================
    # MULTI-TENANT — organization_id
    # --------------------------------------------------------------------------
    # CONSISTENCY FIX: the original scan.py had no FK constraints at all
    # (user_id/target_id were plain strings). This rewrite aligns Scan with
    # every other model: organization_id FK + back_populates relationship,
    # plus real FKs on user_id/target_id with proper relationships.
    # ==========================================================================
    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    organization = db.relationship(
        "Organization",
        backref=db.backref("scans", lazy="select")
    )
    # NOTE: Organization.py does not yet declare a "scans" back_populates
    # pairing. Using backref here is fine ONLY because Organization has no
    # competing `scans = db.relationship(...)` declaration. If you later
    # add one to organization.py, switch this to back_populates="scans"
    # (same pattern as vulnerabilities/targets/exploits/reports/events).

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    target_id = db.Column(
        db.String(36),
        db.ForeignKey("targets.id"),
        nullable=False,
        index=True
    )

    user = db.relationship("User", backref="scans")
    # NOTE: same reasoning as organization above — User does not declare its
    # own "scans" relationship anywhere, so backref is safe (no conflict like
    # the Exploit/Report cases).

    target = db.relationship("Target", backref=db.backref("scans", lazy="dynamic"))
    # lazy="dynamic" mirrors Vulnerability.target's backref (target.vulnerabilities)
    # so target.scans is queryable for "last N scans" without loading everything.

    # ==========================================================================
    # SCAN CONFIG
    # ==========================================================================
    scan_type = db.Column(
        db.Enum(ScanType),
        default=ScanType.FULL,
        nullable=False
    )

    tools = db.Column(db.JSON, default=list)
    # ex: ["nuclei", "subfinder", "httpx"]

    config = db.Column(db.JSON, default=dict)
    # arbitrary scanner config (rate limits, wordlists, scope overrides, etc.)

    # ==========================================================================
    # STATUS SYSTEM
    # ==========================================================================
    status = db.Column(
        db.Enum(ScanStatus),
        default=ScanStatus.QUEUED,
        nullable=False,
        index=True
    )

    progress = db.Column(db.Integer, default=0, nullable=False)
    # 0-100

    error_message = db.Column(db.Text, nullable=True)
    # populated when status == FAILED

    # ==========================================================================
    # RESULTS
    # ==========================================================================
    vulnerabilities_found = db.Column(db.Integer, default=0, nullable=False)

    # ==========================================================================
    # TIMESTAMPS
    # ==========================================================================
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # ORG SAFETY
    # ==========================================================================

    def belongs_to_org(self, org_id: str) -> bool:
        """
        Vérifie que ce scan appartient bien à l'organisation donnée.

        Usage côté service AVANT toute lecture/écriture :
            if not scan.belongs_to_org(current_user.organization_id):
                abort(404)
        """
        return self.organization_id == org_id

    # ==========================================================================
    # LIFECYCLE METHODS
    # --------------------------------------------------------------------------
    # These mirror Target.mark_scan_started/completed/failed() (target.py) —
    # call BOTH when transitioning a scan, so target.last_scan_at /
    # target.last_scan_status stay in sync with the scan record itself.
    #
    # Usage (from a service):
    #     scan.mark_started()
    #     scan.target.mark_scan_started()
    #     db.session.commit()
    # ==========================================================================

    def mark_started(self):
        """Transition QUEUED -> RUNNING."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()
        self.progress = 0

    def mark_completed(self, vulnerabilities_found: int = 0):
        """Transition RUNNING -> COMPLETED, set results + completed_at."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress = 100
        self.vulnerabilities_found = vulnerabilities_found

    def mark_failed(self, error_message: str = None):
        """Transition -> FAILED, record error_message."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = error_message

    def mark_cancelled(self):
        """Transition -> CANCELLED (e.g. user-initiated stop)."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.utcnow()

    def update_progress(self, progress: int):
        """
        Met à jour le pourcentage d'avancement (0-100).
        Clampé pour éviter des valeurs invalides venant du worker.
        """
        self.progress = max(0, min(100, progress))

    # ==========================================================================
    # SERIALIZATION
    # ==========================================================================

    def to_dict(self):
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "user_id": self.user_id,
            "target_id": self.target_id,

            "scan_type": self.scan_type.value if self.scan_type else None,
            "tools": self.tools,
            "config": self.config,

            "status": self.status.value if self.status else None,
            "progress": self.progress,
            "error_message": self.error_message,

            "vulnerabilities_found": self.vulnerabilities_found,

            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }

    def to_simple_dict(self):
        return {
            "id": self.id,
            "target_id": self.target_id,
            "scan_type": self.scan_type.value if self.scan_type else None,
            "status": self.status.value if self.status else None,
            "progress": self.progress,
            "vulnerabilities_found": self.vulnerabilities_found,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Scan {self.id} | target={self.target_id} | status={self.status.value if self.status else '?'}>"