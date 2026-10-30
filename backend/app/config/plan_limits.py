"""
Plan Limits - Single Source of Truth

Previously duplicated across three files with drifting field names and
values:
    - app/tasks/scanner.py       -> PLAN_LIMITS (rate_limit, timeout_minutes, scans_per_day)
    - app/services/scan_service.py -> PLAN_LIMITS (scans_per_day only)
    - app/routes/billing.py      -> PLANS (price, max_members, max_targets,
                                    max_scans_per_day, description)

This drift was real, not hypothetical: billing.py's Stripe prices (29/99/299)
did not match the actual Stripe Dashboard prices (9/29/99) configured for
this project, and scan_service.py's "free" tier said 10 scans/day while
scanner.py said 15 for the exact same plan.

Every module that needs plan limits should import PLAN_LIMITS from here
instead of defining its own copy. If a limit needs to change, it changes
in exactly one place.
"""

PLAN_LIMITS = {
    "free": {
        "name": "Free",
        "price": 0,
        "currency": "USD",
        "scans_per_day": 3,
        "rate_limit": 10,
        "timeout_minutes": 15,
        "max_members": 1,
        "max_targets": 5,
        "description": "Perfect for individuals getting started",
    },
    "starter": {
        "name": "Starter",
        "price": 9,
        "currency": "USD",
        "scans_per_day": 5,
        "rate_limit": 15,
        "timeout_minutes": 20,
        "max_members": 5,
        "max_targets": 25,
        "description": "Small team bug bounty hunting",
    },
    "pro": {
        "name": "Professional",
        "price": 29,
        "currency": "USD",
        "scans_per_day": 20,
        "rate_limit": 25,
        "timeout_minutes": 30,
        "max_members": 50,
        "max_targets": 100,
        "description": "Growing security research team",
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 99,
        "currency": "USD",
        "scans_per_day": 999,
        "rate_limit": 100,
        "timeout_minutes": 60,
        "max_members": 500,
        "max_targets": 1000,
        "description": "Full-scale penetration testing operation",
    },
}


def get_plan_limits(plan: str) -> dict:
    """
    Returns the limits dict for a plan name, falling back to "free" for
    any unrecognized/missing plan value instead of raising a KeyError —
    matches the defensive .get(plan, PLAN_LIMITS["free"]) pattern already
    used at every call site before this refactor.
    """
    return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])