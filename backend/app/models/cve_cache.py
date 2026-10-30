"""
CveCache - Local cache of NVD (National Vulnerability Database) data.

Avoids re-querying the NVD API for the same CVE across multiple scans/
organizations. NVD has a strict rate limit (50 req/30s even with an API
key), so caching is required, not optional, once you have more than a
handful of scans running.

One row per CVE ID — shared across all organizations (CVE data is public,
not org-specific). Refreshed automatically when data is older than
max_age_days (default 30).

What real SaaS platforms (Snyk, Tenable, Qualys) do that this mirrors:
  - Cache CVE data locally to avoid rate-limiting
  - Track fetch failures to avoid infinite retries
  - Store both CVSS v2 and v3 (many old CVEs only have v2)
  - Store EPSS score (probability of real-world exploitation)
  - Index on severity/fetched_at for dashboard queries
"""

from datetime import datetime, timedelta
from typing import Optional
from app import db


class CveCache(db.Model):
    __tablename__ = "cve_cache"

    __table_args__ = (
        # Speeds up "find all stale entries" queries (background refresh job)
        db.Index("idx_cve_cache_fetched_at", "fetched_at"),
        # Speeds up "show all critical CVEs" dashboard queries
        db.Index("idx_cve_cache_severity",   "severity"),
    )

    # CVE ID is the primary key — e.g. "CVE-2025-46817"
    # ← FIX: String(20) was too short. Modern CVE IDs can have long
    # sequence numbers (e.g. "CVE-2026-1234567" = 17 chars), so 30 gives
    # comfortable headroom for any year/sequence-length combination.
    cve_id = db.Column(db.String(30), primary_key=True)

    # ==========================================================================
    # CORE VULNERABILITY DATA (from NVD)
    # ==========================================================================

    description = db.Column(db.Text,        nullable=True)

    # CVSS v3 (2015+) — preferred
    cvss_score  = db.Column(db.Float,       nullable=True)  # 0.0 - 10.0
    cvss_vector = db.Column(db.String(100), nullable=True)  # CVSS:3.1/AV:N/...

    # CVSS v2 (pre-2015) — fallback for old CVEs
    # Many CVEs from 2000-2015 only have v2 scores. Without this, you'd
    # display null for a large portion of historical vulnerabilities.
    cvss_v2_score  = db.Column(db.Float,       nullable=True)
    cvss_v2_vector = db.Column(db.String(100), nullable=True)

    # Severity string (derived from cvss_score for fast filtering)
    severity = db.Column(db.String(20), nullable=True)
    # "critical" (9.0-10.0) / "high" (7.0-8.9) / "medium" (4.0-6.9)
    # "low" (0.1-3.9) / "none" (0.0)

    # CWE classification — important for vulnerability taxonomy and compliance
    # reporting (SOC2, ISO27001 clients will ask for this)
    # e.g. "CWE-78" (OS Command Injection), "CWE-89" (SQL Injection)
    cwe_id = db.Column(db.String(50), nullable=True)

    # ==========================================================================
    # EPSS SCORE (from FIRST.org)
    # --------------------------------------------------------------------------
    # Exploit Prediction Scoring System — probability that this CVE will be
    # exploited in the wild in the next 30 days (0.0 - 1.0).
    # This is what separates amateur tools from professional SaaS:
    #   CVSS says "how bad is it theoretically"
    #   EPSS says "is anyone actually exploiting this RIGHT NOW"
    # Example: CVE-2021-44228 (Log4Shell) had EPSS ~0.97 = 97% exploitation
    # ==========================================================================
    epss_score       = db.Column(db.Float, nullable=True)
    epss_percentile  = db.Column(db.Float, nullable=True)  # rank vs all CVEs

    # ==========================================================================
    # AFFECTED PRODUCTS (CPE)
    # --------------------------------------------------------------------------
    # List of affected product/version combinations in CPE format.
    # Useful for automatically matching Nuclei tech-detect findings with
    # known-vulnerable versions of the same software.
    # Example: ["cpe:2.3:a:php:php:5.3.11:*:*:*:*:*:*:*"]
    # ==========================================================================
    affected_products = db.Column(db.JSON, nullable=True)

    # Official references (list of URLs from NVD)
    references = db.Column(db.JSON, nullable=True)

    # ==========================================================================
    # DATES FROM NVD
    # ==========================================================================
    published_date      = db.Column(db.DateTime, nullable=True)
    last_modified_date  = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # CACHE METADATA
    # --------------------------------------------------------------------------
    # Tracks fetch history so we don't retry endlessly on NVD errors or for
    # CVE IDs that don't exist in NVD (e.g. some Nuclei template IDs look
    # like CVEs but aren't registered in NVD).
    # ==========================================================================
    fetched_at     = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    fetch_attempts = db.Column(db.Integer,  default=0,               nullable=False)
    last_error     = db.Column(db.String(200), nullable=True)

    # If True, NVD confirmed this CVE ID doesn't exist — don't retry for 7 days
    not_found = db.Column(db.Boolean, default=False, nullable=False)

    # ==========================================================================
    # METHODS
    # ==========================================================================

    def is_stale(self, max_age_days: int = 30) -> bool:
        """
        Returns True if cached data should be refreshed.

        Normal CVEs: refresh after 30 days (NVD updates scores/refs over time)
        Not-found CVEs: retry after 7 days (NVD adds new CVEs daily)

        Usage:
            cache = CveCache.query.get("CVE-2025-46817")
            if cache is None or cache.is_stale():
                cache = enrich_with_nvd("CVE-2025-46817")
        """
        age = (datetime.utcnow() - self.fetched_at).days

        if self.not_found:
            return age > 7  # retry not-found after 7 days

        return age > max_age_days

    def effective_cvss_score(self) -> Optional[float]:
        # ← FIX: "float | None" syntax requires Python 3.10+. Using
        # typing.Optional[float] instead works on any Python 3.x version,
        # so this doesn't silently break if the deployment environment
        # ever runs an older interpreter than your local 3.10.
        """
        Returns the best available CVSS score.
        Prefers v3 (more accurate), falls back to v2 (covers old CVEs).
        """
        return self.cvss_score or self.cvss_v2_score

    def effective_severity(self) -> str:
        """
        Derives severity from CVSS score if not stored explicitly.
        Follows NVD's official severity ranges.
        """
        if self.severity:
            return self.severity

        score = self.effective_cvss_score()
        if score is None:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "none"

    def to_dict(self) -> dict:
        return {
            "cve_id":             self.cve_id,
            "description":        self.description,

            "cvss_score":         self.cvss_score,
            "cvss_vector":        self.cvss_vector,
            "cvss_v2_score":      self.cvss_v2_score,
            "cvss_v2_vector":     self.cvss_v2_vector,
            "severity":           self.effective_severity(),

            "cwe_id":             self.cwe_id,
            "epss_score":         self.epss_score,
            "epss_percentile":    self.epss_percentile,

            "affected_products":  self.affected_products,
            "references":         self.references,

            "published_date":     self.published_date.isoformat()     if self.published_date     else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,
            "fetched_at":         self.fetched_at.isoformat(),

            "not_found":          self.not_found,
        }

    def __repr__(self):
        return (
            f"<CveCache {self.cve_id} "
            f"cvss={self.effective_cvss_score()} "
            f"severity={self.effective_severity()}>"
        )