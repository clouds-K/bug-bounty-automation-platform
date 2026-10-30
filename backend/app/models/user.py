from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func
import uuid
import secrets
import hashlib


# ==============================================================================
# TABLE ORGANIZATION (Multi-Tenant)
# ==============================================================================
# Représente une entreprise cliente dans le système SaaS.
# Chaque User appartient à une Organisation — c'est la base du multi-tenancy.
# Un seul Organization peut regrouper plusieurs utilisateurs (ex: équipe red team).
# ==============================================================================




# ==============================================================================
# PLAN LIMITS — Quotas par plan SaaS
# ==============================================================================
# Centraliser ici (pas dans les routes) pour avoir une seule source de vérité.
# À terme : charger depuis DB ou config si les plans deviennent dynamiques.
# ==============================================================================
PLAN_LIMITS = {
    #              api_requests/month  max_targets  max_scans/day
    "free":       {"api_requests": 500,  "targets": 3,   "scans": 5},
    "starter":    {"api_requests": 5_000, "targets": 20,  "scans": 50},
    "pro":        {"api_requests": 50_000, "targets": 100, "scans": 500},
    "enterprise": {"api_requests": -1,    "targets": -1,  "scans": -1},
    # -1 = unlimited
}


# ==============================================================================
# TABLE USER (SaaS-Ready, Multi-Tenant, Stripe, Security)
# ==============================================================================
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MULTI-TENANT SAFETY RULE                                                  ║
# ║  ALL QUERIES ON THIS TABLE MUST FILTER BY organization_id                  ║
# ║                                                                             ║
# ║  ✅  User.query.filter_by(organization_id=org_id, email=email).first()     ║
# ║  ❌  User.query.filter_by(email=email).first()   ← DATA LEAK INTER-ORGS   ║
# ║                                                                             ║
# ║  Toute query sans organization_id = fuite de données entre tenants.        ║
# ║  Appliquer ce filtre au niveau service/repository, jamais dans les routes. ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# ==============================================================================
class User(db.Model):
    __tablename__ = "users"

    # ==========================================================================
    # UNIQUE CONSTRAINTS + INDEX COMPOSITES (Multi-Tenant Performance)
    # --------------------------------------------------------------------------
    # Pourquoi des contraintes composites (email, org_id) plutôt que global ?
    #   → Dans un SaaS multi-tenant, le même email peut exister dans 2 orgs
    #     différentes (ex: consultant qui travaille sur plusieurs comptes).
    #     Un UNIQUE global sur email seul bloquerait ce cas légitime.
    #
    # Pourquoi des index composites (org_id, email) ?
    #   → Toutes les queries SaaS filtrent d'abord par org_id, puis par email
    #     ou username. L'index composite couvre les 2 colonnes en une seule
    #     structure B-tree → lookup O(log n) au lieu de full scan.
    #     Sans cet index, chaque login dans une org = full scan de la table.
    # ==========================================================================
    __table_args__ = (
        # Unicité email par organisation (pas globale — voir commentaire ci-dessus)
        db.UniqueConstraint("email", "organization_id", name="uq_email_org"),
        # Unicité username par organisation
        db.UniqueConstraint("username", "organization_id", name="uq_username_org"),
        # Index composite pour les lookups login (org_id → email)
        db.Index("idx_user_org_email",    "organization_id", "email"),
        # Index composite pour les lookups username (org_id → username)
        db.Index("idx_user_org_username", "organization_id", "username"),
    )

    # ==========================================================================
    # 1. IDENTIFIANT UNIQUE
    # UUID v4 — portable, pas devinable, compatible multi-DB
    # ==========================================================================
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # ==========================================================================
    # 2. MULTI-TENANT — Clé FK vers Organization
    # Nullable=True : permet les comptes individuels sans organisation
    # Index simple conservé pour les queries par org_id seul (ex: list members)
    # --------------------------------------------------------------------------
    # SOFT-DELETE PATTERN (IMPORTANT SaaS) :
    #   → On ne supprime JAMAIS une Organization en DB (données billing, audit).
    #   → On pose organization.is_deleted = True à la place.
    #   → ondelete="RESTRICT" bloque toute suppression accidentelle au niveau DB.
    #   → Si tu veux "désactiver" une org : organization.is_active = False.
    # ==========================================================================
    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="RESTRICT"),
        # RESTRICT = le DB refuse physiquement de supprimer une org avec des users
        # → Force l'usage du soft-delete (is_deleted=True) côté applicatif
        nullable=True,  # NULL = utilisateur solo (plan individuel)
        index=True      # Index simple pour queries type "list all users of org X"
    )

    # Relation explicite vers Organization (back_populates = cohérence bidirectionnelle)
    organization = db.relationship(
        "Organization",
        back_populates="members",
        foreign_keys=[organization_id]
    )

    # ==========================================================================
    # 3. AUTH IDENTIFIERS
    # Contrainte unique globale SUPPRIMÉE (remplacée par uq_email_org ci-dessus)
    # Index simple conservé pour les cas de lookup sans contexte org (admin BO)
    # ==========================================================================
    username = db.Column(
        db.String(50),
        nullable=False,
        index=True      # Index simple pour back-office superadmin uniquement
    )

    email = db.Column(
        db.String(255),
        nullable=False,
        index=True      # Index simple pour back-office superadmin uniquement
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    email_verified = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    # ==========================================================================
    # 4. PROFIL
    # ==========================================================================
    first_name = db.Column(db.String(100))
    last_name  = db.Column(db.String(100))

    # ==========================================================================
    # 5. RBAC — Rôles
    # "user"       : accès standard
    # "admin"      : accès admin de l'organisation
    # "superadmin" : accès back-office SaaS (équipe interne uniquement)
    # ==========================================================================
    role = db.Column(
        db.String(20),
        default="user",
        nullable=False
    )

    # ==========================================================================
    # 6. SAAS PLAN INDIVIDUEL
    # Peut être surchargé par le plan de l'organisation (cf. Organization.plan)
    # free | starter | pro | enterprise
    # ==========================================================================
    plan = db.Column(
        db.String(20),
        default="free",
        nullable=False
    )

    # ==========================================================================
    # 7. BILLING / SUBSCRIPTION METADATA (Stripe-Ready)
    # stripe_customer_id    : ID Stripe côté client (ex: cus_Abc123)
    # stripe_subscription_id: ID Stripe de l'abonnement actif (ex: sub_Xyz789)
    # subscription_status   : active | past_due | canceled | trialing | paused
    # ==========================================================================
    stripe_customer_id = db.Column(
        db.String(100),
        unique=True,
        nullable=True   # NULL tant que l'user n'a pas de carte enregistrée
    )

    stripe_subscription_id = db.Column(
        db.String(100),
        unique=True,
        nullable=True
    )

    subscription_status = db.Column(
        db.String(20),
        default="active",
        nullable=False
        # Valeurs : "active" | "trialing" | "past_due" | "canceled" | "paused"
    )

    # ==========================================================================
    # 8. API USAGE TRACKING (Rate Limiting SaaS)
    # api_requests_count : compteur de requêtes depuis le dernier reset
    # api_last_reset     : timestamp du dernier reset (ex: 1er du mois)
    #
    # Permet d'implémenter des quotas par plan (ex: free = 100 req/mois)
    # sans dépendance externe (Redis/Celery) pour commencer.
    # ==========================================================================
    api_requests_count = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    api_last_reset = db.Column(
        db.DateTime,
        nullable=True   # NULL = jamais reset (compte tout depuis la création)
    )

    # ==========================================================================
    # 9. SÉCURITÉ — API Key (HASHED + PREFIX)
    # --------------------------------------------------------------------------
    # POURQUOI HASHER L'API KEY ?
    #   → Même principe que les mots de passe : si la DB fuite, l'attaquant
    #     ne doit pas pouvoir utiliser les clés directement.
    #   → On stocke uniquement le SHA-256 du token, jamais le token brut.
    #   → Le token en clair est retourné UNE SEULE FOIS à la création,
    #     puis jeté. L'utilisateur doit le sauvegarder lui-même.
    #
    # POURQUOI UN PREFIX ?
    #   → Lookup rapide : au lieu de hasher le token entier pour trouver l'user,
    #     on filtre d'abord par prefix (8 chars, indexé) → quelques rows max,
    #     puis on vérifie le hash sur ces rows seulement.
    #   → Meilleure UX : l'user voit "sk_Abc12345..." dans son dashboard
    #     et peut identifier quel key il utilise sans exposer le secret.
    #   → Pattern utilisé par Stripe, GitHub, OpenAI pour leurs API keys.
    #
    # FORMAT DU TOKEN GÉNÉRÉ :
    #   sk_<8 chars prefix>_<56 chars secret>
    #   ex: "sk_a3f7c291_4d8e...rest_of_56_hex_chars"
    #        ↑ stocké en clair   ↑ seul le hash SHA-256 du token complet est stocké
    #
    # FLUX :
    #   1. generate_api_key() → génère token brut + extrait prefix + stocke hash
    #   2. Retourner le token brut à l'user (une seule fois)
    #   3. Auth : filter_by(api_key_prefix=token[:10]) → vérify_api_key(token)
    # ==========================================================================

    # Prefix du key (8 hex chars, en clair) — pour lookup rapide sans hash scan
    api_key_prefix = db.Column(
        db.String(11),   # "sk_" + 8 chars = 10 chars max
        nullable=True,
        index=True       # Index pour le lookup rapide (étape 1 de l'auth)
    )

    # Hash SHA-256 du token complet — pour vérification sécurisée (étape 2)
    api_key_hash = db.Column(
        db.String(64),   # SHA-256 = 64 hex chars
        unique=True,
        index=True,
        nullable=True
    )

    # Timestamp de création/rotation du key (audit : détecte les keys anciennes)
    # Utile pour forcer rotation tous les 90 jours, ou pour l'UI "generated X ago"
    api_key_created_at = db.Column(
        db.DateTime,
        nullable=True    # NULL = pas encore de key générée
    )

    # ==========================================================================
    # 10. SECURITY LOGGING — Brute-Force Protection
    # failed_login_attempts : incrémenté à chaque échec de login
    # locked_until          : si non-NULL et dans le futur → compte verrouillé
    #
    # Règle recommandée : après 5 échecs → lock 15 min (exponentiel possible)
    # ==========================================================================
    failed_login_attempts = db.Column(
        db.Integer,
        default=0,
        nullable=False
    )

    locked_until = db.Column(
        db.DateTime,
        nullable=True   # NULL = compte non verrouillé
    )

    # --- IP du dernier login (audit trail, détection de compte compromis) ---
    last_login_ip = db.Column(
        db.String(45),  # 45 chars = supporte IPv6 complet
        nullable=True
    )

    # ==========================================================================
    # 11. ÉTAT DU COMPTE
    # is_active  : False = compte désactivé manuellement par admin
    # is_deleted : True  = soft-delete (RGPD : anonymiser, pas supprimer)
    # ==========================================================================
    is_active  = db.Column(db.Boolean, default=True,  nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    # ==========================================================================
    # 12. TIMESTAMPS — Audit & Activité Utilisateur
    # last_login_at    : dernière connexion réussie (auth)
    # last_activity_at : dernière action dans l'app (middleware @track_activity)
    # created_at       : immuable, enregistré par le DB server
    # updated_at       : auto-mis à jour à chaque save()
    # ==========================================================================
    last_login_at    = db.Column(db.DateTime, nullable=True)
    last_activity_at = db.Column(db.DateTime, nullable=True)

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
    # 13. RELATIONS (données appartenant à cet utilisateur)
    # ==========================================================================
    targets         = db.relationship("Target",        backref="owner", lazy=True)
 
    # NOTE: vulnerability.py declares
    #   user = db.relationship("User", back_populates="vulnerabilities")
    # so this side MUST use back_populates="user" with explicit foreign_keys,
    # since Vulnerability now has TWO FKs to User (user_id and
    # assigned_to_id) -- without foreign_keys this relationship is ambiguous.
    vulnerabilities = db.relationship(
        "Vulnerability",
        back_populates="user",
        foreign_keys="[Vulnerability.user_id]",
        lazy=True
    )
 
    # Reverse side of Vulnerability.assigned_to
    assigned_vulnerabilities = db.relationship(
        "Vulnerability",
        back_populates="assigned_to",
        foreign_keys="[Vulnerability.assigned_to_id]",
        lazy=True
    )
 
    # NOTE: exploit.py now declares
    #   user = db.relationship("User", back_populates="exploits")
    # (changed from backref="exploits"). This side MUST use
    # back_populates="user" -- otherwise both files try to own
    # User.exploits and SQLAlchemy raises a mapper configuration error
    # at startup.
    exploits        = db.relationship("Exploit", back_populates="user", lazy=True)
 
    reports         = db.relationship("Report",        backref="user",  lazy=True)

    # ==========================================================================
    # MÉTHODES DE SÉCURITÉ
    # ==========================================================================

    def set_password(self, password: str):
        """Hash le mot de passe avec PBKDF2-SHA256 + salt de 16 bytes."""
        self.password_hash = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=16
        )

    def check_password(self, password: str) -> bool:
        """Vérifie le mot de passe contre le hash stocké."""
        return check_password_hash(self.password_hash, password)

    # --------------------------------------------------------------------------
    # API KEY — Hashed storage
    # --------------------------------------------------------------------------
    @staticmethod
    def _hash_api_key(raw_key: str) -> str:
        """SHA-256 du token brut. Utilisé pour le stockage ET la vérification."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def generate_api_key(self) -> str:
        """
        Génère un nouveau API key au format : sk_<8chars>_<56chars>
        → Stocke le PREFIX (en clair, pour lookup) et le HASH (pour vérif).
        → Met à jour api_key_created_at.
        → Retourne le token BRUT (à afficher une seule fois à l'utilisateur).

        Exemple d'usage dans la route :
            raw_key = user.generate_api_key()
            db.session.commit()
            return jsonify({"api_key": raw_key, "message": "Save it — shown once"})
        """
        from datetime import datetime
        prefix              = secrets.token_hex(4)          # 8 hex chars
        secret              = secrets.token_hex(28)         # 56 hex chars
        raw_key             = f"sk_{prefix}_{secret}"       # token complet
        self.api_key_prefix  = f"sk_{prefix}"               # stocké en clair
        self.api_key_hash    = self._hash_api_key(raw_key)  # hash du token complet
        self.api_key_created_at = datetime.utcnow()
        return raw_key  # ← afficher UNE SEULE FOIS, ne jamais stocker

    def regenerate_api_key(self) -> str:
        """Révoque l'ancien key et en génère un nouveau. Même flux que generate."""
        return self.generate_api_key()

    def verify_api_key(self, raw_key: str) -> bool:
        """
        Vérifie un API key reçu dans une requête.

        Usage recommandé dans le middleware d'auth (lookup en 2 étapes) :
            prefix = raw_key[:10]   # "sk_" + 8 chars
            user = User.query.filter_by(
                api_key_prefix=prefix,
                organization_id=org_id   # ← TOUJOURS filtrer par org
            ).first()
            if user and user.verify_api_key(raw_key):
                ...  # auth OK

        Étape 1 (filter_by prefix) : utilise l'index → quelques rows max.
        Étape 2 (verify_api_key)   : vérifie le hash sur ces rows seulement.
        """
        if not self.api_key_hash:
            return False
        return self.api_key_hash == self._hash_api_key(raw_key)

    # --------------------------------------------------------------------------
    # BRUTE-FORCE PROTECTION
    # --------------------------------------------------------------------------
    def record_failed_login(self):
        """
        Incrémente le compteur d'échecs.
        Après 5 tentatives : lock 15 min (peut être rendu exponentiel).
        """
        from datetime import datetime, timedelta
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

    def reset_failed_logins(self):
        """Réinitialise le compteur après un login réussi."""
        self.failed_login_attempts = 0
        self.locked_until          = None

    def is_locked(self) -> bool:
        """Retourne True si le compte est actuellement verrouillé."""
        from datetime import datetime
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    # --------------------------------------------------------------------------
    # API USAGE TRACKING
    # --------------------------------------------------------------------------
    def increment_api_usage(self):
        """Incrémente le compteur de requêtes API pour le rate limiting."""
        self.api_requests_count += 1

    def reset_api_usage(self):
        """Reset mensuel du compteur (appeler via cron ou Celery Beat)."""
        from datetime import datetime
        self.api_requests_count = 0
        self.api_last_reset     = datetime.utcnow()

    def get_plan_limit(self, resource: str) -> int:
        """
        Retourne la limite du plan actuel pour une ressource donnée.
        Resources : "api_requests" | "targets" | "scans"
        Retourne -1 pour unlimited (plan enterprise).

        Usage : limit = user.get_plan_limit("api_requests")  → 50000
        """
        return PLAN_LIMITS.get(self.plan, PLAN_LIMITS["free"]).get(resource, 0)

    def has_api_quota(self) -> bool:
        """
        Vérifie si l'user a encore du quota API ce mois-ci.
        Retourne True si sous la limite (ou plan unlimited).

        Usage dans le middleware de rate limiting :
            if not current_user.has_api_quota():
                abort(429, "Monthly API quota exceeded. Upgrade your plan.")
            current_user.increment_api_usage()
            db.session.commit()
        """
        limit = self.get_plan_limit("api_requests")
        if limit == -1:
            return True  # enterprise = unlimited
        return self.api_requests_count < limit

    # ==========================================================================
    # SERIALIZATION
    # api_key_hash et stripe_* exclus volontairement du to_dict() public
    # ==========================================================================
    def to_dict(self):
        return {
            "id":                    self.id,
            "username":              self.username,
            "email":                 self.email,
            "first_name":            self.first_name,
            "last_name":             self.last_name,
            "role":                  self.role,
            "plan":                  self.plan,
            "organization_id":       self.organization_id,
            "email_verified":        self.email_verified,
            "subscription_status":   self.subscription_status,
            "api_requests_count":    self.api_requests_count,
            "is_active":             self.is_active,
            "is_locked":             self.is_locked(),
            "api_key_created_at": (
                self.api_key_created_at.isoformat() if self.api_key_created_at else None
            ),
            "last_login_at": (
                self.last_login_at.isoformat() if self.last_login_at else None
            ),
            "last_activity_at": (
                self.last_activity_at.isoformat() if self.last_activity_at else None
            ),
            "created_at":  self.created_at.isoformat(),
            "updated_at":  self.updated_at.isoformat()
        }

    def __repr__(self):
        return f"<User {self.username} | org={self.organization_id} | plan={self.plan}>"