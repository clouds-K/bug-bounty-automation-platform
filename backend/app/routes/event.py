"""
Event Routes - Audit Trail & Activity Log

READ-ONLY endpoints for querying organization activity history.
Events are immutable - they are only created via services, never updated or deleted.
This is the foundation for compliance, notifications, and event sourcing patterns.

All queries are org-scoped by organization_id for multi-tenant safety.


"""

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.error_responses import error_response, success_response, paginated_response, ErrorCode
import logging

logger = logging.getLogger("bug_bounty")
event_bp = Blueprint("events", __name__, url_prefix="/api/events")


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    """Extract current user from JWT token."""
    return User.query.get(get_jwt_identity())


def parse_datetime(date_string: str):
    """Parse ISO 8601 datetime string."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


# ==============================================================================
# LIST ORGANIZATION EVENTS (org-wide activity feed)
# ==============================================================================

@event_bp.route("", methods=["GET"])
@jwt_required()
def list_events():
    """
    GET /api/events
    
    Get organization-wide activity feed with filtering and pagination.
    Most recent events first. Read-only endpoint.
    
    Query parameters:
        skip: int (default: 0)
        limit: int (default: 50, max: 200)
        entity_type: str (filter by entity type) [optional]
            - vulnerability | target | report | exploit | user | organization
        event_type: str (filter by event type) [optional]
            - vuln.created | vuln.status_changed | vuln.bounty_awarded | etc.
        actor_id: str (filter by who triggered event) [optional]
        source: str (filter by event source) [optional]
            - user | api | scanner | system
        entity_id: str (filter by specific entity) [optional]
        since: ISO 8601 datetime (filter events after this time) [optional]
        until: ISO 8601 datetime (filter events before this time) [optional]
    
    Response:
        200: {
            "success": true,
            "data": {
                "events": [{...}, ...],
                "pagination": {...}
            }
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        # Pagination
        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(ErrorCode.INVALID_FORMAT, "skip/limit must be integers", 400)
        
        if skip < 0:
            return error_response(ErrorCode.INVALID_RANGE, "skip must be >= 0", 400)
        
        limit = max(1, min(limit, 200))
        
        # Base query: all events for this org, most recent first
        query = Event.query.filter_by(organization_id=org.id)
        
        # Optional filters
        
        # Filter by entity type
        entity_type_filter = request.args.get("entity_type")
        if entity_type_filter:
            try:
                entity_type_enum = EntityType[entity_type_filter.upper()]
                query = query.filter_by(entity_type=entity_type_enum)
            except KeyError:
                return error_response(
                    ErrorCode.INVALID_ENUM,
                    f"entity_type must be one of: {', '.join([e.value for e in EntityType])}",
                    400
                )
        
        # Filter by event type
        event_type_filter = request.args.get("event_type")
        if event_type_filter:
            try:
                event_type_enum = EventType[event_type_filter.upper()]
                query = query.filter_by(event_type=event_type_enum)
            except KeyError:
                return error_response(
                    ErrorCode.INVALID_ENUM,
                    f"event_type must be a valid EventType",
                    400
                )
        
        # Filter by actor (who triggered the event)
        actor_id_filter = request.args.get("actor_id")
        if actor_id_filter:
            query = query.filter_by(actor_id=actor_id_filter)
        
        # Filter by source (user, api, scanner, system)
        source_filter = request.args.get("source")
        if source_filter:
            try:
                source_enum = EventSource[source_filter.upper()]
                query = query.filter_by(source=source_enum)
            except KeyError:
                return error_response(
                    ErrorCode.INVALID_ENUM,
                    f"source must be one of: {', '.join([s.value for s in EventSource])}",
                    400
                )
        
        # Filter by specific entity
        entity_id_filter = request.args.get("entity_id")
        if entity_id_filter:
            query = query.filter_by(entity_id=entity_id_filter)
        
        # Filter by time range
        since = request.args.get("since")
        if since:
            since_dt = parse_datetime(since)
            if not since_dt:
                return error_response(ErrorCode.INVALID_FORMAT, "since must be ISO 8601 datetime", 400)
            query = query.filter(Event.created_at >= since_dt)
        
        until = request.args.get("until")
        if until:
            until_dt = parse_datetime(until)
            if not until_dt:
                return error_response(ErrorCode.INVALID_FORMAT, "until must be ISO 8601 datetime", 400)
            query = query.filter(Event.created_at <= until_dt)
        
        # Get total count before pagination
        total = query.count()
        
        # Order by created_at DESC (most recent first) and paginate
        events = query.order_by(Event.created_at.desc()).offset(skip).limit(limit).all()
        
        return paginated_response(
            [e.to_dict() for e in events],
            total, skip, limit,
            "Events retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to list events: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list events", 500)


# ==============================================================================
# GET EVENTS FOR SPECIFIC ENTITY (activity for one resource)
# ==============================================================================

@event_bp.route("/entity/<entity_type>/<entity_id>", methods=["GET"])
@jwt_required()
def get_entity_events(entity_type, entity_id):
    """
    GET /api/events/entity/<entity_type>/<entity_id>
    
    Get complete activity history for a single entity (vulnerability, target, etc.).
    Useful for showing "what happened to this vulnerability" timeline.
    
    Parameters:
        entity_type: vulnerability | target | report | exploit | user | organization
        entity_id: UUID of the entity
    
    Query parameters:
        skip: int (default: 0)
        limit: int (default: 50, max: 200)
    
    Response:
        200: {
            "success": true,
            "data": {
                "entity_type": "vulnerability",
                "entity_id": "vuln-uuid",
                "events": [{...}, ...],
                "pagination": {...}
            }
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        # Validate entity type
        try:
            entity_type_enum = EntityType[entity_type.upper()]
        except KeyError:
            return error_response(
                ErrorCode.INVALID_ENUM,
                f"entity_type must be one of: {', '.join([e.value for e in EntityType])}",
                400
            )
        
        # Pagination
        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(ErrorCode.INVALID_FORMAT, "skip/limit must be integers", 400)
        
        limit = max(1, min(limit, 200))
        
        # Query events for this entity (org-scoped for safety)
        query = Event.query.filter_by(
            organization_id=org.id,
            entity_type=entity_type_enum,
            entity_id=entity_id
        )
        
        total = query.count()
        events = query.order_by(Event.created_at.desc()).offset(skip).limit(limit).all()
        
        return paginated_response(
            [e.to_dict() for e in events],
            total, skip, limit,
            f"Activity for {entity_type}:{entity_id}"
        )
    
    except Exception as e:
        logger.error(f"Failed to get entity events: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get entity events", 500)


# ==============================================================================
# GET USER ACTIVITY (audit trail for specific user)
# ==============================================================================

@event_bp.route("/user/<user_id>", methods=["GET"])
@jwt_required()
def get_user_activity(user_id):
    """
    GET /api/events/user/<user_id>
    
    Get all actions performed by a specific user (audit trail).
    Useful for: compliance, investigating suspicious activity, user analytics.
    
    Parameters:
        user_id: UUID of the user
    
    Query parameters:
        skip: int (default: 0)
        limit: int (default: 50, max: 200)
        event_type: str (filter by event type) [optional]
    
    Response:
        200: {
            "success": true,
            "data": {
                "actor_id": "user-uuid",
                "events": [{...}, ...],
                "pagination": {...}
            }
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        # Verify target user exists and is in same org
        target_user = User.query.filter_by(
            id=user_id,
            organization_id=org.id,
            is_deleted=False
        ).first()
        
        if not target_user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        # Pagination
        try:
            skip = int(request.args.get("skip", 0))
            limit = int(request.args.get("limit", 50))
        except ValueError:
            return error_response(ErrorCode.INVALID_FORMAT, "skip/limit must be integers", 400)
        
        limit = max(1, min(limit, 200))
        
        # Query events triggered by this user
        query = Event.query.filter_by(
            organization_id=org.id,
            actor_id=user_id
        )
        
        # Optional event type filter
        event_type_filter = request.args.get("event_type")
        if event_type_filter:
            try:
                event_type_enum = EventType[event_type_filter.upper()]
                query = query.filter_by(event_type=event_type_enum)
            except KeyError:
                return error_response(ErrorCode.INVALID_ENUM, "Invalid event_type", 400)
        
        total = query.count()
        events = query.order_by(Event.created_at.desc()).offset(skip).limit(limit).all()
        
        return paginated_response(
            [e.to_dict() for e in events],
            total, skip, limit,
            f"Activity by user {target_user.username}"
        )
    
    except Exception as e:
        logger.error(f"Failed to get user activity: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get user activity", 500)


# ==============================================================================
# GET SINGLE EVENT
# ==============================================================================

@event_bp.route("/<event_id>", methods=["GET"])
@jwt_required()
def get_event(event_id):
    """
    GET /api/events/<event_id>
    
    Get details of a specific event.
    
    Response:
        200: {"success": true, "data": {"event": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        # Query with org-scoping for safety
        event = Event.query.filter_by(
            id=event_id,
            organization_id=org.id
        ).first()
        
        if not event:
            return error_response(ErrorCode.NOT_FOUND, "Event not found", 404)
        
        return success_response(
            {"event": event.to_dict()},
            "Event retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get event: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get event", 500)


# ==============================================================================
# GET STATISTICS & METRICS
# ==============================================================================

@event_bp.route("/stats/summary", methods=["GET"])
@jwt_required()
def get_event_stats():
    """
    GET /api/events/stats/summary
    
    Get high-level statistics about organization activity.
    Useful for dashboards and activity summaries.
    
    Query parameters:
        days: int (number of days to look back, default: 7)
    
    Response:
        200: {
            "success": true,
            "data": {
                "total_events": 1250,
                "events_today": 42,
                "events_this_week": 250,
                "events_by_type": {
                    "vuln.created": 120,
                    "vuln.status_changed": 85,
                    ...
                },
                "events_by_source": {
                    "user": 1000,
                    "scanner": 200,
                    "system": 50
                },
                "top_actors": [
                    {"user_id": "...", "username": "alice", "action_count": 450},
                    ...
                ]
            }
        }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        try:
            days = int(request.args.get("days", 7))
        except ValueError:
            days = 7
        
        if days < 1 or days > 365:
            return error_response(ErrorCode.INVALID_RANGE, "days must be between 1-365", 400)
        
        from datetime import datetime, timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Total events in org
        all_events = Event.query.filter_by(organization_id=org.id)
        total_events = all_events.count()
        
        # Events in time period
        period_events = all_events.filter(Event.created_at >= cutoff_date)
        period_count = period_events.count()
        
        # Events by type (in period)
        events_by_type = {}
        for event_type in EventType:
            count = period_events.filter_by(event_type=event_type).count()
            if count > 0:
                events_by_type[event_type.value] = count
        
        # Events by source (in period)
        events_by_source = {}
        for source in EventSource:
            count = period_events.filter_by(source=source).count()
            if count > 0:
                events_by_source[source.value] = count
        
        # Top actors (most active users)
        from sqlalchemy import func
        top_actors_query = db.session.query(
            Event.actor_id,
            func.count(Event.id).label('action_count')
        ).filter(
            Event.organization_id == org.id,
            Event.created_at >= cutoff_date,
            Event.actor_id.isnot(None)
        ).group_by(Event.actor_id).order_by(
            func.count(Event.id).desc()
        ).limit(5).all()
        
        top_actors = []
        for actor_id, count in top_actors_query:
            actor_user = User.query.get(actor_id)
            if actor_user:
                top_actors.append({
                    "user_id": actor_id,
                    "username": actor_user.username,
                    "action_count": count
                })
        
        # Today's events
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_count = all_events.filter(Event.created_at >= today).count()
        
        return success_response(
            {
                "stats": {
                    "total_events": total_events,
                    "events_period": period_count,
                    "period_days": days,
                    "events_today": today_count,
                    "events_by_type": events_by_type,
                    "events_by_source": events_by_source,
                    "top_actors": top_actors
                }
            },
            "Event statistics retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get event stats: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get event stats", 500)