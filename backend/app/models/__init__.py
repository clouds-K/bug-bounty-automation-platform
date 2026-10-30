"""
Models package - Import all models
Central registry for all ORM models and enums
"""

# ==========================
# MODEL IMPORTS
# ==========================

# --- Organization (multi-tenant foundation) ---
from app.models.organization import Organization

# --- User (with RBAC) ---
from app.models.user import User

# --- Targets ---
from app.models.target import Target
from app.models.cve_cache import CveCache


# --- Vulnerabilities (with workflow) ---
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityType,
    SeverityLevel,
    VulnerabilityStatus,
    TriageStatus,
    VisibilityLevel,
    ALLOWED_TRANSITIONS
)

# --- Exploits ---
from app.models.exploit import (
    Exploit,
    ExploitStatus,
    ExploitType
)

# --- Reports ---
from app.models.report import (
    Report,
    ReportStatus,
    ReportPlatform
)

# --- Scans ---
from app.models.scan import (
    Scan,
    ScanStatus,
    ScanType
)

# --- Event Sourcing ---
from app.models.event import (
    Event,
    EntityType,
    EventType,
    EventSource
)

 # --- Bounties ---
from app.models.bounty import (
    Bounty,
    BountyStatus,
    PaymentMethod
    )


# ==========================
# EXPORTS
# ==========================

__all__ = [
    # Core entities
    "Organization",
    "User",
    "Target",
    "CveCache",
    "Vulnerability",
    "Exploit",
    "Report",
    "Scan",
    "Event",

    # Vulnerability enums
    "VulnerabilityType",
    "SeverityLevel",
    "VulnerabilityStatus",
    "TriageStatus",
    "VisibilityLevel",
    "ALLOWED_TRANSITIONS",

    # Exploit enums
    "ExploitStatus",
    "ExploitType",

    # Report enums
    "ReportStatus",
    "ReportPlatform",

    # Scan enums
    "ScanStatus",
    "ScanType",

    # Event enums
    "EntityType",
    "EventType",
    "EventSource",
    
    "Bounty",       
    "BountyStatus", 
    "PaymentMethod",
] 