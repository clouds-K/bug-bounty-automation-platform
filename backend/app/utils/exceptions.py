"""
Custom exceptions for application logic.
Thrown by services, caught by routes, converted to error_response().

Pattern:
    # In a service:
    raise NotFoundError("Vulnerability not found")

    # In a route:
    except NotFoundError as e:
        return error_response(ErrorCode.NOT_FOUND, str(e), 404)
"""


class AppException(Exception):
    """Base exception for all application errors."""
    error_code = "INTERNAL_ERROR"
    status_code = 500
    message = "An unexpected error occurred"


class AuthenticationError(AppException):
    """User authentication failed."""
    error_code = "INVALID_CREDENTIALS"
    status_code = 401


class AuthorizationError(AppException):
    """User is authenticated but lacks permission."""
    error_code = "FORBIDDEN"
    status_code = 403


class NotFoundError(AppException):
    """Resource does not exist or is not visible to this user."""
    error_code = "NOT_FOUND"
    status_code = 404


class ConflictError(AppException):
    """Resource already exists or state conflict."""
    error_code = "CONFLICT"
    status_code = 409


class ValidationError(AppException):
    """Input validation failed."""
    error_code = "VALIDATION_ERROR"
    status_code = 400


class PlanLimitExceededError(AppException):
    """User has exceeded their plan limits."""
    error_code = "PLAN_LIMIT_EXCEEDED"
    status_code = 429


class CrossOrgViolation(AppException):
    """Attempted cross-organization data access."""
    error_code = "FORBIDDEN"
    status_code = 403
    message = "You do not have access to this resource"


class DatabaseError(AppException):
    """Database operation failed."""
    error_code = "DATABASE_ERROR"
    status_code = 500


class ExternalServiceError(AppException):
    """Third-party service (Stripe, email, etc.) failed."""
    error_code = "EXTERNAL_SERVICE_ERROR"
    status_code = 503