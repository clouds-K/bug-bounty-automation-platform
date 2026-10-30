from functools import wraps
from datetime import datetime
from flask import request, g, abort, jsonify
from app import db


# ==============================================================================
# MIDDLEWARE — Activity Tracking + API Auth + Rate Limiting
# ==============================================================================
#
# Ce fichier centralise 3 responsabilités :
#   1. track_activity   : met à jour last_activity_at à chaque requête authentifiée
#   2. require_api_key  : authentifie les requêtes API via X-API-Key header
#   3. require_auth     : authentifie les requêtes session (JWT ou Flask-Login)
#
# Usage dans app.py :
#   from middleware import register_middleware
#   register_middleware(app)
#
# Usage dans les routes :
#   @app.route("/api/scans")
#   @require_api_key          ← vérifie key + quota + injecte g.current_user
#   @require_permission("scan:create")
#   def create_scan(): ...
# ==============================================================================


def register_middleware(app):
    """
    Enregistre les hooks Flask globaux.
    Appeler une seule fois dans app.py après création de l'app.
    """

    @app.before_request
    def _track_activity():
        """
        Met à jour last_activity_at sur chaque requête authentifiée.

        Pourquoi before_request et pas after_request ?
        → before_request s'exécute avant la route. Si on met ça en after_request,
          une route lente de 2s retarde inutilement le commit du timestamp.
          Ici on update en début de requête, flush sans commit complet (perf).

        Pourquoi flush() et pas commit() ?
        → commit() ouvre/ferme une transaction complète.
          flush() écrit en DB dans la transaction courante sans la fermer.
          Le commit final de la route englobe les deux → une seule transaction.
        """
        # g.current_user est injecté par require_api_key ou require_auth
        user = getattr(g, "current_user", None)
        if user is not None:
            user.last_activity_at = datetime.utcnow()
            db.session.flush()   # écrit sans commit — le commit vient de la route


# ==============================================================================
# DECORATOR — require_api_key
# ==============================================================================
def require_api_key(f):
    """
    Authentifie une requête via le header X-API-Key.

    Flux complet :
      1. Lit X-API-Key depuis les headers
      2. Extrait le prefix (10 premiers chars : "sk_xxxxxxxx")
      3. Lookup DB par prefix (index) → candidates
      4. Vérifie le hash SHA-256 sur les candidates
      5. Vérifie quota API (has_api_quota)
      6. Incrémente le compteur d'usage
      7. Injecte l'user dans g.current_user pour la route

    Erreurs retournées :
      401 : key manquante ou invalide
      403 : compte désactivé ou org supprimée
      429 : quota mensuel dépassé
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # FIX: was "from models.user import User" — your package is
        # "app.models", not "models". This import path must match how
        # app/models/__init__.py and the rest of the project are structured.
        from app.models.user import User

        raw_key = request.headers.get("X-API-Key", "").strip()

        # --- 1. Présence du header ---
        if not raw_key:
            return jsonify({"error": "Missing X-API-Key header"}), 401

        # --- 2. Format minimal attendu : "sk_" + 8 chars + "_" = 12 chars min ---
        if len(raw_key) < 12 or not raw_key.startswith("sk_"):
            return jsonify({"error": "Invalid API key format"}), 401

        # --- 3. Lookup par prefix (rapide, indexé) ---
        prefix = raw_key[:11]   # "sk_" (3) + 8 hex chars = 11 chars total
        # MULTI-TENANT SAFETY : on ne filtre PAS encore par org ici car le prefix
        # est déjà unique globalement (8 hex chars aléatoires = 4 milliards de combos).
        # Si tu passes à un modèle org-scoped, ajouter organization_id ici.
        candidates = User.query.filter_by(
            api_key_prefix=prefix,
            is_deleted=False,
            is_active=True
        ).all()

        # --- 4. Vérification du hash sur les candidates ---
        user = None
        for candidate in candidates:
            if candidate.verify_api_key(raw_key):
                user = candidate
                break

        if user is None:
            return jsonify({"error": "Invalid API key"}), 401

        # --- 5. Vérifications de l'état du compte ---
        if user.is_locked():
            return jsonify({
                "error": "Account temporarily locked",
                "locked_until": user.locked_until.isoformat()
            }), 403

        # Vérifier que l'organisation n'est pas soft-deleted
        if user.organization_id and user.organization:
            if user.organization.is_deleted:
                return jsonify({"error": "Organization is disabled"}), 403

        # --- 6. Quota API ---
        if not user.has_api_quota():
            limit = user.get_plan_limit("api_requests")
            return jsonify({
                "error": "Monthly API quota exceeded",
                "limit": limit,
                "current": user.api_requests_count,
                "upgrade_url": "/billing/upgrade"
            }), 429

        # --- 7. Incrémente usage + injecte dans g ---
        user.increment_api_usage()
        db.session.flush()

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


# ==============================================================================
# DECORATOR — require_auth (session / JWT)
# ==============================================================================
def require_auth(f):
    """
    Authentifie une requête via session Flask ou JWT Bearer token.
    Injecte g.current_user pour les routes web (dashboard, etc.)

    À adapter selon ton système d'auth (Flask-Login, Flask-JWT-Extended, etc.)
    Ce stub montre le pattern — remplace le bloc JWT par ton implémentation.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # FIX: same import path correction as require_api_key above.
        from app.models.user import User

        # --- Tentative JWT Bearer ---
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                # Remplacer par ton décodage JWT réel :
                # payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                # user_id = payload["sub"]
                # user = User.query.get(user_id)
                raise NotImplementedError("Replace with real JWT decode")
            except Exception:
                return jsonify({"error": "Invalid or expired token"}), 401

        # --- Tentative session Flask ---
        from flask import session
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401

        user = User.query.get(user_id)
        if not user or not user.is_active or user.is_deleted:
            return jsonify({"error": "Account not found or disabled"}), 401

        if user.is_locked():
            return jsonify({"error": "Account temporarily locked"}), 403

        g.current_user = user
        return f(*args, **kwargs)

    return decorated