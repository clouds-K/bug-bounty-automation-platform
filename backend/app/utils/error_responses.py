"""
Standardized error and success responses for entire API.
Single source of truth for API response format.
All routes MUST use these helpers, never jsonify() directly.
"""

from flask import jsonify
from enum import Enum
from datetime import datetime
from uuid import uuid4
from typing import Any, Dict, Optional


class ErrorCode(Enum):

    # === Authentication ===
    INVALID_EMAIL             = "INVALID_EMAIL"
    INVALID_PASSWORD          = "INVALID_PASSWORD"
    EMAIL_ALREADY_EXISTS      = "EMAIL_ALREADY_EXISTS"
    USERNAME_ALREADY_EXISTS   = "USERNAME_ALREADY_EXISTS"
    INVALID_CREDENTIALS       = "INVALID_CREDENTIALS"
    ACCOUNT_LOCKED            = "ACCOUNT_LOCKED"
    ACCOUNT_DISABLED          = "ACCOUNT_DISABLED"
    ACCOUNT_DELETED           = "ACCOUNT_DELETED"

    # === Authorization ===
    UNAUTHORIZED              = "UNAUTHORIZED"
    FORBIDDEN                 = "FORBIDDEN"
    PLAN_LIMIT_EXCEEDED       = "PLAN_LIMIT_EXCEEDED"
    INSUFFICIENT_PERMISSIONS  = "INSUFFICIENT_PERMISSIONS"

    # === Resource ===
    NOT_FOUND                 = "NOT_FOUND"
    CONFLICT                  = "CONFLICT"
    ALREADY_EXISTS            = "ALREADY_EXISTS"

    # === Validation ===
    VALIDATION_ERROR          = "VALIDATION_ERROR"
    MISSING_FIELD             = "MISSING_FIELD"
    INVALID_ENUM              = "INVALID_ENUM"
    INVALID_FORMAT            = "INVALID_FORMAT"
    INVALID_RANGE             = "INVALID_RANGE"

    # === Server ===
    INTERNAL_ERROR            = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE       = "SERVICE_UNAVAILABLE"
    DATABASE_ERROR            = "DATABASE_ERROR"
    EXTERNAL_SERVICE_ERROR    = "EXTERNAL_SERVICE_ERROR"


def error_response(
    code: ErrorCode,
    message: str,
    status_code: int,
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
):
    """
    Create standardized error response.

    Usage:
        return error_response(
            ErrorCode.INVALID_EMAIL,
            "The email format is invalid",
            400,
            {"field": "email", "value": "notanemail"}
        )
    """
    return jsonify({
        "success": False,
        "error": {
            "code": code.value,
            "message": message,
            "details": details or {}
        },
        "request_id": request_id or str(uuid4()),
        "timestamp": datetime.utcnow().isoformat()
    }), status_code


def success_response(
    data: Any = None,
    message: Optional[str] = None,
    status_code: int = 200,
    request_id: Optional[str] = None
):
    """
    Create standardized success response.

    Usage:
        return success_response(
            {"user": user.to_dict()},
            "User created successfully",
            201
        )
    """
    response = {
        "success": True,
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id or str(uuid4())
    }

    if message:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return jsonify(response), status_code


def paginated_response(
    items: list,
    total: int,
    skip: int = 0,
    limit: int = 50,
    message: Optional[str] = None,
    status_code: int = 200,
    request_id: Optional[str] = None
):
    """
    Standardized paginated list response.

    Usage:
        return paginated_response(
            [t.to_simple_dict() for t in targets],
            total, skip, limit
        )
    """
    response = {
        "success": True,
        "data": items,
        "pagination": {
            "skip": skip,
            "limit": limit,
            "total": total,
            "count": len(items),
            "has_more": (skip + limit) < total
        },
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id or str(uuid4())
    }

    if message:
        response["message"] = message

    return jsonify(response), status_code