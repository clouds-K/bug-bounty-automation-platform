"""
Target Model - Production SaaS Bug Bounty Platform

Représente une cible bug bounty (program / asset)

Key changes in this version:
  - scan_url: the EXACT URL the scanner should hit (http://localhost:8081, https://example.com/api, etc.)
  - domain: auto-derived from scan_url for filtering/search/display
  - scan_enabled: pause scanning on a target without deleting it
  - scan_config: per-target scanner overrides (rate_limit, timeout_minutes, tools)
"""

from app import db
from sqlalchemy.sql import func
from datetime import datetime
from urllib.parse import urlparse
import uuid


class Target(db.Model):
    """
    Représente une cible bug bounty (program / asset)
    """
    __tablename__ = "targets"

    # ==========================================================================
    # COMPOSITE INDEXES — Multi-Tenant Performance
    # --------------------------------------------------------------------------
    # idx_target_org_status   : "all active targets in org X" (dashboard)
    # idx_target_org_domain   : lookup by domain within an org
    # ==========================================================================
    __table_args__ = (
        db.Index("idx_target_org_status", "organization_id", "status"),
        db.Index("idx_target_org_domain", "organization_id", "domain"),
    )

    # ==========================
    # ID
    # ==========================

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # ==========================================================================
    # MULTI-TENANT — organization_id
    # ==========================================================================
    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    organization = db.relationship(
        "Organization",
        back_populates="targets"
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # ==========================================================================
    # CORE INFO
    # --------------------------------------------------------------------------
    # scan_url : the EXACT URL the scanner should hit, including scheme and
    # port (e.g. "http://localhost:8081", "https://api.example.com/v2").
    # This is the single source of truth for scanning — it replaces the old
    # pattern of guessing f"https://{domain}" in scanner.py, which silently
    # produced the wrong URL for any target running on HTTP, a non-standard
    # port, or a sub-path.
    #
    # domain : kept for filtering/search/dashboards. Auto-populated from
    # scan_url via extract_domain_from_url() so it never has to be entered
    # twice or can drift out of sync.
    # ==========================================================================

    scan_url = db.Column(
        db.String(500),
        nullable=False
    )

    domain = db.Column(
        db.String(255),
        nullable=False,
        index=True
    )

    program_name = db.Column(db.String(255))
    description = db.Column(db.Text)

    # ==========================
    # PLATFORM
    # ==========================

    platform = db.Column(
        db.String(50),
        default="custom",
        nullable=False
    )
    # hackerone / bugcrowd / etc

    program_url = db.Column(db.String(500))

    # ==========================
    # SCOPE
    # ==========================

    scope = db.Column(db.Text)
    in_scope = db.Column(db.Text)
    out_of_scope = db.Column(db.Text)

    # ==========================
    # REWARD SYSTEM
    # ==========================

    rewards_min = db.Column(db.Float, default=0.0)
    rewards_max = db.Column(db.Float, default=0.0)

    # ==========================
    # STATUS
    # ==========================

    status = db.Column(
        db.String(20),
        default="active",
        nullable=False
    )
    # active / completed / on_hold / archived

    is_verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    # ==========================================================================
    # SCAN CONTROL
    # --------------------------------------------------------------------------
    # scan_enabled : lets a customer pause scanning on a target without
    # deleting it (e.g. target temporarily down for maintenance, or a
    # customer asked to pause testing). The scan-creation route should
    # check this before dispatching to Celery.
    #
    # scan_config : per-target override of scanner defaults (rate_limit,
    # timeout_minutes, tools). Falls back to Scan.config / global defaults
    # when null. Centralizing this on Target means a customer can set
    # "always scan this target gently" once instead of on every Scan.
    # ==========================================================================
    scan_enabled = db.Column(db.Boolean, default=True, nullable=False)
    scan_config = db.Column(db.JSON, nullable=True)

    # ==========================================================================
    # SOFT DELETE
    # ==========================================================================
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # SCAN LIFECYCLE (SaaS scanner compatibility)
    # ==========================================================================
    last_scan_at = db.Column(db.DateTime, nullable=True)
    last_scan_status = db.Column(db.String(50), default="never_scanned")
    # never_scanned / running / completed / failed

    # ==========================================================================
    # VULNERABILITY COUNTERS (cached, dashboard-critical)
    # ==========================================================================
    vuln_count_total = db.Column(db.Integer, default=0, nullable=False)
    vuln_count_critical = db.Column(db.Integer, default=0, nullable=False)
    vuln_count_high = db.Column(db.Integer, default=0, nullable=False)

    # ==========================================================================
    # SLA AGGREGATION
    # ==========================================================================
    sla_breached_count = db.Column(db.Integer, default=0, nullable=False)
    avg_fix_time_hours = db.Column(db.Float, default=0.0)

    # ==========================
    # SaaS UPGRADE FIELD
    # ==========================

    risk_score = db.Column(
        db.Float,
        default=0.0
    )

    asset_type = db.Column(
        db.String(50)
    )
    # web / api / mobile / infra

    # ==========================
    # NOTES
    # ==========================

    notes = db.Column(db.Text)

    # ==========================
    # AUDIT
    # ==========================

    last_scanned = db.Column(db.DateTime)

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
    # URL / DOMAIN HELPERS
    # ==========================================================================

    @staticmethod
    def extract_domain_from_url(url: str) -> str:
        """
        Extract just the hostname from a scan_url for storage in `domain`.

        Examples:
            "http://localhost:8081"          -> "localhost"
            "https://api.example.com/v2"     -> "api.example.com"
            "https://example.com"            -> "example.com"

        Falls back to the raw string if parsing fails (e.g. a bare domain
        was passed without a scheme), so domain is never left empty.
        """
        if not url:
            return ""
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            return parsed.hostname or url
        except Exception:
            return url

    def sync_domain_from_scan_url(self):
        """
        Keeps `domain` in sync with `scan_url`. Call this whenever scan_url
        is set or changed (in the service layer, before commit).

        Usage:
            target.scan_url = "http://localhost:8081"
            target.sync_domain_from_scan_url()
            db.session.commit()
        """
        self.domain = self.extract_domain_from_url(self.scan_url)

    # ==========================================================================
    # ORG SAFETY
    # ==========================================================================

    def belongs_to_org(self, org_id: str) -> bool:
        """
        Vérifie que ce target appartient bien à l'organisation donnée.

        Usage côté service AVANT toute lecture/écriture :
            if not target.belongs_to_org(current_user.organization_id):
                abort(404)  # ne pas révéler l'existence cross-org
        """
        return self.organization_id == org_id

    # ==========================================================================
    # SOFT DELETE
    # ==========================================================================

    def soft_delete(self):
        """
        Désactive le target sans le supprimer physiquement.
        Préserve l'historique des vulnérabilités/exploits/reports liés.

        Usage :
            target.soft_delete()
            db.session.commit()
        """
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()

    # ==========================================================================
    # VULN STATS
    # ==========================================================================

    def update_vuln_stats(self):
        """
        Recalcule les compteurs de vulnérabilités pour ce target.
        Nécessite que Vulnerability.target soit lazy="dynamic" (cf.
        vulnerability.py) pour que self.vulnerabilities soit une Query.

        N'inclut volontairement PAS les vulnérabilités soft-deleted
        (is_deleted=False) dans les compteurs.

        Usage (depuis le service layer, après create/update/delete d'une
        vulnérabilité) :
            target.update_vuln_stats()
            db.session.commit()
        """
        from app.models.vulnerability import SeverityLevel

        active_vulns = self.vulnerabilities.filter_by(is_deleted=False)

        self.vuln_count_total = active_vulns.count()
        self.vuln_count_critical = active_vulns.filter_by(
            severity=SeverityLevel.CRITICAL
        ).count()
        self.vuln_count_high = active_vulns.filter_by(
            severity=SeverityLevel.HIGH
        ).count()

    # ==========================================================================
    # SCAN LIFECYCLE
    # ==========================================================================

    def mark_scan_started(self):
        """Appelé au début d'un scan (manuel ou automatisé)."""
        self.last_scan_at = datetime.utcnow()
        self.last_scan_status = "running"

    def mark_scan_completed(self):
        """Appelé à la fin d'un scan réussi."""
        self.last_scan_at = datetime.utcnow()
        self.last_scan_status = "completed"
        self.last_scanned = self.last_scan_at

    def mark_scan_failed(self):
        """Appelé si un scan échoue (erreur, timeout, etc.)."""
        self.last_scan_at = datetime.utcnow()
        self.last_scan_status = "failed"

    # ==========================
    # SERIALIZATION
    # ==========================

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "user_id": self.user_id,
            "scan_url": self.scan_url,
            "domain": self.domain,
            "program_name": self.program_name,
            "description": self.description,
            "platform": self.platform,
            "program_url": self.program_url,
            "scope": self.scope,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "rewards_min": self.rewards_min,
            "rewards_max": self.rewards_max,
            "status": self.status,
            "is_verified": self.is_verified,

            "scan_enabled": self.scan_enabled,
            "scan_config": self.scan_config,

            "is_deleted": self.is_deleted,
            "deleted_at": (
                self.deleted_at.isoformat() if self.deleted_at else None
            ),

            "last_scan_at": (
                self.last_scan_at.isoformat() if self.last_scan_at else None
            ),
            "last_scan_status": self.last_scan_status,

            "vuln_count_total": self.vuln_count_total,
            "vuln_count_critical": self.vuln_count_critical,
            "vuln_count_high": self.vuln_count_high,

            "sla_breached_count": self.sla_breached_count,
            "avg_fix_time_hours": self.avg_fix_time_hours,

            "risk_score": self.risk_score,
            "asset_type": self.asset_type,
            "notes": self.notes,
            "last_scanned": (
                self.last_scanned.isoformat()
                if self.last_scanned else None
            ),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def to_simple_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_url": self.scan_url,
            "domain": self.domain,
            "program_name": self.program_name,
            "platform": self.platform,
            "status": self.status,
            "scan_enabled": self.scan_enabled,
            "risk_score": self.risk_score,
            "vuln_count_total": self.vuln_count_total,
            "vuln_count_critical": self.vuln_count_critical,
            "last_scan_status": self.last_scan_status,
            "created_at": self.created_at.isoformat()
        }

    def __repr__(self):
        return f"<Target {self.domain} | org={self.organization_id}>"