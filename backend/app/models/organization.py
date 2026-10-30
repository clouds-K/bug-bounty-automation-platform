"""
Modèle Organization - Foundation multi-tenant SaaS
Représente une entreprise cliente
"""

from app import db
from sqlalchemy.sql import func
import uuid
from datetime import datetime


class Organization(db.Model):
    """
    Représente une organisation cliente (entreprise, équipe, etc.)
    Chaque User appartient à une Organization.
    Toutes les données (Target, Vulnerability, etc.) sont scopées par org.
    """
    __tablename__ = "organizations"

    # ==========================
    # ID
    # ==========================
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # ==========================
    # ORG INFO
    # ==========================
    name = db.Column(
        db.String(255),
        nullable=False,
        unique=True,
        index=True
    )

    slug = db.Column(
        db.String(100),
        unique=True,
        index=True,
        nullable=False
    )
    # URL-friendly slug (ex: acme-corp → /org/acme-corp)

    description = db.Column(db.Text)

    # ==========================
    # PLAN & SUBSCRIPTION
    # ==========================
    plan = db.Column(
        db.String(20),
        default="free",
        nullable=False
    )
    # free / starter / pro / enterprise

    # Stripe integration
    stripe_customer_id = db.Column(
        db.String(100),
        unique=True,
        nullable=True,
        index=True
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
    )
    # active / trialing / past_due / canceled / paused

    # ==========================
    # LIMITS
    # ==========================
    max_members = db.Column(
        db.Integer,
        default=5,
        nullable=False
    )
    # Nombre max de membres (dépend du plan)

    max_targets = db.Column(
        db.Integer,
        default=10
    )

    max_scans_per_day = db.Column(
        db.Integer,
        default=5
    )

    # ==========================
    # STATUS
    # ==========================
    is_active = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )

    is_deleted = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    deleted_at = db.Column(db.DateTime, nullable=True)

    # ==========================
    # TIMESTAMPS
    # ==========================
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
    # RELATIONSHIPS
    # --------------------------------------------------------------------------
    # Organization is the SINGLE OWNER of these org-scoped relationships.
    # Each child model (User, Target, Vulnerability, Exploit, Report, Event)
    # declares the matching back_populates side:
    #
    #   User.organization          -> back_populates="members"
    #   Target.organization         -> back_populates="targets"
    #   Vulnerability.organization  -> back_populates="vulnerabilities"
    #   Exploit.organization        -> back_populates="exploits"
    #   Report.organization         -> back_populates="reports"
    #   Event.organization          -> back_populates="events"
    #
    # IMPORTANT: do NOT declare `organization = db.relationship("Organization",
    # backref=db.backref("..."))` on the child side — that creates a SECOND,
    # competing definition of the same attribute and crashes at mapper
    # configuration time. back_populates requires the pairing to be declared
    # on BOTH sides, with matching names.
    # ==========================================================================
    members = db.relationship(
        "User",
        back_populates="organization",
        lazy="select"
    )

    targets = db.relationship(
        "Target",
        back_populates="organization",
        lazy="select"
    )

    vulnerabilities = db.relationship(
        "Vulnerability",
        back_populates="organization",
        lazy="select"
    )

    exploits = db.relationship(
        "Exploit",
        back_populates="organization",
        lazy="select"
    )

    reports = db.relationship(
        "Report",
        back_populates="organization",
        lazy="select"
    )

    events = db.relationship(
        "Event",
        back_populates="organization",
        lazy="select"
    )

    # ==========================
    # METHODS
    # ==========================

    def soft_delete(self):
        """
        Soft delete l'organisation sans supprimer les données.
        IMPORTANT : preserves billing history, audit trail.

        Usage :
            org.soft_delete()
            db.session.commit()
        """
        self.is_deleted = True
        self.is_active = False
        self.deleted_at = datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "description": self.description,
            "plan": self.plan,
            "subscription_status": self.subscription_status,
            "max_members": self.max_members,
            "max_targets": self.max_targets,
            "max_scans_per_day": self.max_scans_per_day,
            "is_active": self.is_active,
            "is_deleted": self.is_deleted,
            "deleted_at": (
                self.deleted_at.isoformat() if self.deleted_at else None
            ),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def to_simple_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "plan": self.plan,
            "subscription_status": self.subscription_status,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat()
        }

    def __repr__(self) -> str:
        return f"<Organization {self.name} | plan={self.plan}>"