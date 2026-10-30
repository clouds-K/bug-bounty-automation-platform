from functools import wraps
from flask import g, jsonify



# ==============================================================================
# RBAC — Role-Based Access Control (Granulaire)
# ==============================================================================
#
# Architecture en 2 couches :
#
#   Couche 1 — ROLES (qui es-tu ?)
#     "user"       : hunter standard, accès à ses propres ressources
#     "admin"      : admin d'une organisation, gère les membres et paramètres
#     "superadmin" : équipe interne SaaS, accès back-office global
#
#   Couche 2 — PERMISSIONS (que peux-tu faire ?)
#     Granulaires, vérifiables individuellement.
#     Format : "resource:action"  ex: "scan:create", "report:export"
#
# Pourquoi 2 couches et pas juste des rôles ?
#   → Les rôles évoluent (ex: "junior hunter" sans droit d'export)
#     mais ajouter un rôle pour chaque variante = explosion combinatoire.
#   → Les permissions permettent de dire exactement "ce user peut X mais pas Y"
#     sans créer un rôle dédié.
#
# Intégration avec User model :
#   Les permissions sont DÉRIVÉES du rôle (pas stockées en DB pour l'instant).
#   get_permissions(user) → set de permissions selon user.role + user.plan.
#   Évolution future : table UserPermission pour overrides individuels.
#
# Usage dans les routes :
#   @require_api_key
#   @require_permission("scan:create")
#   def create_scan(): ...
#
#   @require_auth
#   @require_role("admin")
#   def manage_team(): ...
# ==============================================================================


# ==============================================================================
# PERMISSION DEFINITIONS
# ==============================================================================
# Toutes les permissions possibles du système.
# Documenter ici évite les fautes de frappe dispersées dans les routes.
# ==============================================================================

class P:
    """
    Namespace de toutes les permissions.
    Usage : P.SCAN_CREATE, P.REPORT_EXPORT, etc.
    """
    # --- Targets (cibles de bug bounty) ---
    TARGET_CREATE  = "target:create"
    TARGET_READ    = "target:read"
    TARGET_UPDATE  = "target:update"
    TARGET_DELETE  = "target:delete"

    # --- Scans ---
    SCAN_CREATE    = "scan:create"
    SCAN_READ      = "scan:read"
    SCAN_CANCEL    = "scan:cancel"

    # --- Vulnerabilities ---
    VULN_CREATE    = "vulnerability:create"
    VULN_READ      = "vulnerability:read"
    VULN_UPDATE    = "vulnerability:update"
    VULN_DELETE    = "vulnerability:delete"
    VULN_VERIFY    = "vulnerability:verify"    # admin only : marquer comme vérifié

    # --- Reports ---
    REPORT_CREATE  = "report:create"
    REPORT_READ    = "report:read"
    REPORT_EXPORT  = "report:export"           # pro+ only
    REPORT_SHARE   = "report:share"            # pro+ only

    # --- Exploits ---
    EXPLOIT_CREATE = "exploit:create"
    EXPLOIT_READ   = "exploit:read"
    EXPLOIT_DELETE = "exploit:delete"

    # --- Organisation (admin) ---
    ORG_READ       = "org:read"
    ORG_UPDATE     = "org:update"
    ORG_INVITE     = "org:invite_member"
    ORG_REMOVE     = "org:remove_member"
    ORG_BILLING    = "org:manage_billing"

    # --- Back-office (superadmin uniquement) ---
    ADMIN_USERS    = "admin:manage_users"
    ADMIN_ORGS     = "admin:manage_orgs"
    ADMIN_BILLING  = "admin:manage_billing"
    ADMIN_LOGS     = "admin:view_logs"


# ==============================================================================
# ROLE → PERMISSIONS MAPPING
# ==============================================================================
# Source unique de vérité : quel rôle donne accès à quelles permissions.
# Les permissions sont ADDITIVES (on commence depuis "user", on monte).
# ==============================================================================

# Permissions de base : tout utilisateur authentifié
_BASE_PERMISSIONS = {
    P.TARGET_CREATE, P.TARGET_READ, P.TARGET_UPDATE, P.TARGET_DELETE,
    P.SCAN_CREATE,   P.SCAN_READ,   P.SCAN_CANCEL,
    P.VULN_CREATE,   P.VULN_READ,   P.VULN_UPDATE,   P.VULN_DELETE,
    P.REPORT_CREATE, P.REPORT_READ,
    P.EXPLOIT_CREATE, P.EXPLOIT_READ, P.EXPLOIT_DELETE,
    P.ORG_READ,
}

# Permissions supplémentaires selon le plan (features payantes)
_PLAN_EXTRA_PERMISSIONS = {
    "free":       set(),
    "starter":    {P.REPORT_EXPORT},
    "pro":        {P.REPORT_EXPORT, P.REPORT_SHARE},
    "enterprise": {P.REPORT_EXPORT, P.REPORT_SHARE},
}

# Permissions supplémentaires selon le rôle
_ROLE_EXTRA_PERMISSIONS = {
    "user": set(),
    "admin": {
        P.VULN_VERIFY,
        P.ORG_UPDATE, P.ORG_INVITE, P.ORG_REMOVE, P.ORG_BILLING,
    },
    "superadmin": {
        P.VULN_VERIFY,
        P.ORG_UPDATE, P.ORG_INVITE, P.ORG_REMOVE, P.ORG_BILLING,
        P.ADMIN_USERS, P.ADMIN_ORGS, P.ADMIN_BILLING, P.ADMIN_LOGS,
    },
}


def get_permissions(user) -> set:
    """
    Retourne le set complet des permissions d'un user.
    Combinaison de : base + plan + rôle.

    Usage :
        perms = get_permissions(current_user)
        if P.REPORT_EXPORT in perms:
            ...

    Évolution future : fusionner avec des overrides individuels depuis DB.
        individual_overrides = {p.permission for p in user.permission_overrides}
        return base | plan_extra | role_extra | individual_overrides
    """
    base       = _BASE_PERMISSIONS.copy()
    plan_extra = _PLAN_EXTRA_PERMISSIONS.get(user.plan, set())
    role_extra = _ROLE_EXTRA_PERMISSIONS.get(user.role, set())
    return base | plan_extra | role_extra


def has_permission(user, permission: str) -> bool:
    """
    Vérifie si un user a une permission spécifique.

    Usage direct (hors decorator) :
        if has_permission(current_user, P.REPORT_EXPORT):
            include_pdf_link = True
    """
    return permission in get_permissions(user)


# ==============================================================================
# DECORATORS
# ==============================================================================

def require_permission(permission: str):
    """
    Vérifie qu'un utilisateur authentifié (via JWT) possède une permission
    spécifique, dérivée de son rôle et de son plan d'abonnement.

    Usage :
        @bounty_bp.route("/<bounty_id>/approve", methods=["POST"])
        @jwt_required()
        @require_permission(P.VULN_VERIFY)
        def approve_bounty(bounty_id): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
            from app.models.user import User

            # S'assure qu'un JWT valide est présent, même si @jwt_required()
            # n'est pas déjà appliqué au-dessus (defensive, pas de duplication
            # d'erreur si déjà vérifié).
            verify_jwt_in_request()

            user = User.query.get(get_jwt_identity())
            if not user:
                return jsonify({"error": "Authentication required"}), 401

            if not has_permission(user, permission):
                return jsonify({
                    "error": "Permission denied",
                    "required": permission,
                    "your_plan": user.plan,
                    "your_role": user.role,
                    "upgrade_url": "/billing/upgrade"
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_role(role: str):
    """
    Vérifie qu'un utilisateur a exactement ce rôle ou un rôle supérieur.
    Hiérarchie : user < admin < superadmin

    Usage :
        @app.route("/api/org/members")
        @require_auth
        @require_role("admin")
        def manage_members(): ...
    """
    ROLE_HIERARCHY = {"user": 0, "admin": 1, "superadmin": 2}

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            user_level     = ROLE_HIERARCHY.get(user.role, 0)
            required_level = ROLE_HIERARCHY.get(role, 99)

            if user_level < required_level:
                return jsonify({
                    "error": "Insufficient role",
                    "required": role,
                    "yours": user.role
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_same_org(f):
    """
    Vérifie que la ressource accédée appartient à la même organisation que l'user.
    La route doit passer organization_id dans kwargs (via URL ou param).

    Usage :
        @app.route("/api/orgs/<organization_id>/targets")
        @require_api_key
        @require_same_org
        def list_targets(organization_id): ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = getattr(g, "current_user", None)
        if user is None:
            return jsonify({"error": "Authentication required"}), 401

        # Les superadmins ont accès cross-org (back-office)
        if user.role == "superadmin":
            return f(*args, **kwargs)

        # Récupère organization_id depuis les kwargs de la route
        org_id = kwargs.get("organization_id")
        if org_id and user.organization_id != org_id:
            # MULTI-TENANT SAFETY : ne pas révéler que la ressource existe
            return jsonify({"error": "Resource not found"}), 404

        return f(*args, **kwargs)
    return decorated