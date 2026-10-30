"""
Modèle Event - Append-only event log (Production SaaS Bug Bounty Platform)

==============================================================================
PURPOSE
==============================================================================
This is the backbone for:
  - 4.2 Event sourcing      : queryable history across the whole org,
                               not locked inside per-row JSON blobs.
  - 4.3 Notifications        : a notification worker can poll/subscribe to
                               new Event rows and dispatch email/webhooks.
  - 4.1 RBAC / audit         : "who did what, when" across every entity type.
  - 4.4 API safety layer     : services emit one Event per meaningful action,
                               giving you a single choke point for analytics
                               and outbound integrations.

Design choice: a SINGLE generic `events` table (entity_type/entity_id) rather
than one event table per entity. This keeps the schema simple, makes
cross-entity activity feeds trivial ("show me everything that happened in
org X today"), and avoids a migration every time a new entity type needs
event tracking.

This table is ADDITIVE — it does not replace Vulnerability.status_history.
status_history stays as a fast, denormalized "history for THIS row" view.
The events table is the source of truth for cross-entity queries,
notifications, and analytics. Services should write to both via
EventLog.record(...) at the same call site as log_status_change().
==============================================================================
"""

from app import db
from sqlalchemy.sql import func
import uuid
from enum import Enum


# ==============================================================================
# ENUMS
# ==============================================================================

class EntityType(Enum):
    VULNERABILITY = "vulnerability"
    TARGET        = "target"
    REPORT        = "report"
    EXPLOIT       = "exploit"
    USER          = "user"
    ORGANIZATION  = "organization"


class EventType(Enum):
    # --- Vulnerability lifecycle ---
    VULN_CREATED        = "vuln.created"
    VULN_STATUS_CHANGED = "vuln.status_changed"
    VULN_ASSIGNED       = "vuln.assigned"
    VULN_UNASSIGNED     = "vuln.unassigned"
    VULN_BOUNTY_AWARDED = "vuln.bounty_awarded"
    VULN_DELETED        = "vuln.deleted"

    # --- Triage ---
    TRIAGE_STATUS_CHANGED = "triage.status_changed"

    # --- User / org lifecycle (useful for RBAC audit + billing events) ---
    USER_ROLE_CHANGED   = "user.role_changed"
    USER_INVITED        = "user.invited"
    ORG_PLAN_CHANGED    = "org.plan_changed"

    # --- Generic fallback ---
    OTHER = "other"


# ==============================================================================
# EVENT SOURCE — who/what triggered the event
# ==============================================================================

class EventSource(Enum):
    USER    = "user"      # human action via UI
    API     = "api"        # external API call (e.g. CI integration)
    SCANNER = "scanner"     # automated scanner / tool
    SYSTEM  = "system"      # internal scheduled job / migration / cron


# ==============================================================================
# MODEL
# ==============================================================================
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  MULTI-TENANT SAFETY RULE                                                  ║
# ║  ALL QUERIES MUST FILTER BY organization_id                                ║
# ║                                                                             ║
# ║  ✅  Event.query.filter_by(organization_id=org_id, ...)                    ║
# ║  ❌  Event.query.filter_by(entity_id=x)  ← DATA LEAK                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# APPEND-ONLY : rows in this table are never updated or deleted by the app.
# No soft-delete fields on purpose — this is the audit log itself.
# ==============================================================================
class Event(db.Model):
    __tablename__ = "events"

    __table_args__ = (
        # Activity feed for a given org, most recent first
        db.Index("idx_event_org_created", "organization_id", "created_at"),
        # "show me everything that happened to this entity"
        db.Index("idx_event_entity", "organization_id", "entity_type", "entity_id"),
        # "show me everything user X did" (audit trail)
        db.Index("idx_event_org_actor", "organization_id", "actor_id"),
        # Notification worker: poll unprocessed events efficiently
        db.Index("idx_event_org_type_created", "organization_id", "event_type", "created_at"),
    )

    # ==========================================================================
    # IDENTIFIERS
    # ==========================================================================
    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    # ==========================================================================
    # MULTI-TENANT — organization_id (CRITIQUE)
    # --------------------------------------------------------------------------
    # nullable=False : every event belongs to an org. Events are never moved
    # or merged across orgs. ondelete="RESTRICT" matches the pattern used in
    # Vulnerability/User — orgs are soft-deleted only, never hard-deleted.
    # ==========================================================================
    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    organization = db.relationship(
        "Organization",
        back_populates="events"
    )

    # ==========================================================================
    # ACTOR — who/what triggered this event
    # --------------------------------------------------------------------------
    # actor_id : nullable, since SYSTEM/SCANNER events have no human actor.
    # ==========================================================================
    actor_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=True,
        index=True
    )

    actor = db.relationship("User", foreign_keys=[actor_id])

    source = db.Column(
        db.Enum(EventSource),
        default=EventSource.USER,
        nullable=False,
        index=True
    )

    # ==========================================================================
    # SUBJECT — what entity this event is about
    # --------------------------------------------------------------------------
    # entity_type + entity_id : generic pointer, NOT a real FK (entity_id can
    # point to vulnerabilities, targets, reports, users, etc.). Application
    # code is responsible for resolving entity_id based on entity_type.
    # ==========================================================================
    entity_type = db.Column(
        db.Enum(EntityType),
        nullable=False,
        index=True
    )

    entity_id = db.Column(
        db.String(36),
        nullable=False,
        index=True
    )

    # ==========================================================================
    # EVENT DETAILS
    # ==========================================================================
    event_type = db.Column(
        db.Enum(EventType),
        nullable=False,
        index=True
    )

    # Free-form structured payload (e.g. {"from": "verified", "to": "reported"}
    # or {"amount": 500, "currency": "USD"}). Keeps this table generic without
    # needing a column per event type.
    payload = db.Column(db.JSON, default=dict)

    # ==========================================================================
    # NOTIFICATION DISPATCH TRACKING (4.3)
    # --------------------------------------------------------------------------
    # notified_at : set once a notification worker has processed this event
    # (sent emails/webhooks for it). NULL = not yet processed.
    # Keeping this here avoids a separate "outbox" table for v1; if dispatch
    # volume grows, this can be split into a dedicated outbox/queue table
    # without touching the event schema itself.
    # ==========================================================================
    notified_at = db.Column(db.DateTime, nullable=True)

    # ==========================================================================
    # TIMESTAMP
    # --------------------------------------------------------------------------
    # Append-only: created_at is the only timestamp. No updated_at.
    # ==========================================================================
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )

    # ==========================================================================
    # FACTORY / CONVENIENCE
    # ==========================================================================

    @classmethod
    def record(cls, organization_id: str, entity_type: EntityType, entity_id: str,
               event_type: EventType, actor_id: str = None,
               source: EventSource = EventSource.USER, payload: dict = None):
        """
        Crée (sans committer) un nouvel Event et le retourne.

        Usage typique (dans un service, juste après log_status_change()) :

            event = Event.record(
                organization_id=vuln.organization_id,
                entity_type=EntityType.VULNERABILITY,
                entity_id=vuln.id,
                event_type=EventType.VULN_STATUS_CHANGED,
                actor_id=current_user.id,
                source=EventSource.USER,
                payload={"from": "verified", "to": "reported"}
            )
            db.session.add(event)
            db.session.commit()

        Ne fait PAS de commit : laisse l'appelant grouper l'event avec les
        autres écritures (vuln.log_status_change(), etc.) dans une seule
        transaction.
        """
        return cls(
            organization_id=organization_id,
            entity_type=entity_type,
            entity_id=entity_id,
            event_type=event_type,
            actor_id=actor_id,
            source=source,
            payload=payload or {}
        )

    # ==========================================================================
    # QUERY HELPERS
    # ==========================================================================

    @classmethod
    def for_entity(cls, organization_id: str, entity_type: EntityType, entity_id: str):
        """Activity feed for a single entity (e.g. one vulnerability), newest first."""
        return cls.query.filter_by(
            organization_id=organization_id,
            entity_type=entity_type,
            entity_id=entity_id
        ).order_by(cls.created_at.desc())

    @classmethod
    def for_org(cls, organization_id: str):
        """Org-wide activity feed, newest first."""
        return cls.query.filter_by(
            organization_id=organization_id
        ).order_by(cls.created_at.desc())

    @classmethod
    def unnotified(cls, organization_id: str = None):
        """
        Events not yet processed by the notification worker (4.3).
        If organization_id is None, returns across ALL orgs — intended for
        use by the background worker only, never by request-scoped code.
        """
        q = cls.query.filter(cls.notified_at.is_(None))
        if organization_id is not None:
            q = q.filter_by(organization_id=organization_id)
        return q.order_by(cls.created_at.asc())

    def mark_notified(self):
        """Called by the notification worker once dispatch succeeds."""
        from datetime import datetime
        self.notified_at = datetime.utcnow()

    # ==========================================================================
    # SERIALIZATION
    # ==========================================================================

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "organization_id": self.organization_id,
            "actor_id":        self.actor_id,
            "source":          self.source.value if self.source else None,
            "entity_type":     self.entity_type.value if self.entity_type else None,
            "entity_id":       self.entity_id,
            "event_type":      self.event_type.value if self.event_type else None,
            "payload":         self.payload,
            "notified_at": (
                self.notified_at.isoformat() if self.notified_at else None
            ),
            "created_at":      self.created_at.isoformat()
        }

    def __repr__(self) -> str:
        return (
            f"<Event {self.event_type.value if self.event_type else '?'} "
            f"on {self.entity_type.value if self.entity_type else '?'}:{self.entity_id} "
            f"org={self.organization_id}>"
        )