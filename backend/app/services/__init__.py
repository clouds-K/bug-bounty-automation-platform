"""
Services package

Two kinds of modules live here:

1. Business-logic services (org-scoped operations + audit trail via Event):
    vulnerability_service  → vuln CRUD + status transitions + assignment
    target_service         → target CRUD + stats sync
    bounty_service         → bounty proposal → approval → payment workflow
    exploit_service        → exploit CRUD + status + confirm
    report_service         → report CRUD + submit → acknowledge → resolv
 

2. Cross-cutting auth/request infrastructure:
   - middleware.py    (register_middleware, require_api_key, require_auth)
   - permissions.py   (RBAC: P, get_permissions, require_permission,
                        require_role, require_same_org)

These two groups serve different purposes, but are exported together here
for convenient importing.
"""

from app.services import vulnerability_service
from app.services import target_service
from app.services import bounty_service
from app.services import exploit_service
from app.services import report_service
from app.services import scan_service




from app.services.middleware import register_middleware, require_api_key, require_auth
from app.services.permissions import (
    P,
    get_permissions,
    has_permission,
    require_permission,
    require_role,
    require_same_org,
)

__all__ = [
    # business-logic services (import as module: `from app.services import bounty_service`)
    "vulnerability_service",
    "target_service",
    "bounty_service",
    "exploit_service",
    "report_service",
     "scan_service",
     
     

    # middleware
    "register_middleware",
    "require_api_key",
    "require_auth",

    # permissions / RBAC
    "P",
    "get_permissions",
    "has_permission",
    "require_permission",
    "require_role",
    "require_same_org",
]