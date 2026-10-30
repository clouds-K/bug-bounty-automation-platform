"""
Billing Routes - Stripe Integration & Subscription Management

Endpoints for managing subscriptions, payment methods, invoices, and handling
Stripe webhooks. Integrates with Stripe API for real payment processing.


"""
from app.config.plan_limits import PLAN_LIMITS as PLANS
from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.user import User
from app.models.organization import Organization
from app.models.event import Event, EntityType, EventType, EventSource
from app.utils.error_responses import error_response, success_response, ErrorCode
import logging
import os
import json
from flask import current_app

logger = logging.getLogger("bug_bounty")
billing_bp = Blueprint("billing", __name__, url_prefix="/api/billing")

# Stripe is optional - will be None if STRIPE_SECRET_KEY not set
try:
    import stripe
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    STRIPE_ENABLED = bool(os.environ.get("STRIPE_SECRET_KEY"))
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
except ImportError:
    stripe = None
    STRIPE_ENABLED = False
    STRIPE_WEBHOOK_SECRET = ""


# ==============================================================================
# HELPERS
# ==============================================================================

def get_current_user() -> User:
    """Extract current user from JWT token."""
    return User.query.get(get_jwt_identity())


def is_admin(user: User) -> bool:
    """Check if user has admin role in their organization."""
    return user and user.role == "admin"




# ==============================================================================
# GET AVAILABLE PLANS
# ==============================================================================

@billing_bp.route("/plans", methods=["GET"])
def get_plans():
    """
    GET /api/billing/plans
    
    List all available subscription plans.
    PUBLIC endpoint - no authentication required.
    
    Response:
        200: {
            "success": true,
            "data": {
                "plans": [
                    {
                        "plan": "free",
                        "name": "Free",
                        "price": 0,
                        "currency": "USD",
                        "max_members": 1,
                        "max_targets": 5,
                        ...
                    },
                    ...
                ]
            }
        }
    """
    try:
        plans_list = []
        for plan_key, plan_data in PLANS.items():
            plans_list.append({
                "plan": plan_key,
                **plan_data
            })
        
        return success_response(
            {"plans": plans_list},
            "Available plans retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get plans: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get plans", 500)


# ==============================================================================
# GET CURRENT SUBSCRIPTION
# ==============================================================================

@billing_bp.route("/subscription", methods=["GET"])
@jwt_required()
def get_subscription():
    """
    GET /api/billing/subscription
    
    Get current organization's subscription and plan details.
    
    Response:
        200: {
            "success": true,
            "data": {
                "subscription": {
                    "plan": "pro",
                    "status": "active",
                    "max_members": 50,
                    "max_targets": 100,
                    "max_scans_per_day": 100,
                    "stripe_subscription_id": "sub_...",
                    "stripe_customer_id": "cus_...",
                    "created_at": "2026-06-18T...",
                    "updated_at": "2026-06-18T..."
                }
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
        
        plan_info = PLANS.get(org.plan, PLANS["free"])
        
        return success_response(
            {
                "subscription": {
                    "plan": org.plan,
                    "plan_name": plan_info.get("name"),
                    "status": org.subscription_status,
                    "max_members": org.max_members,
                    "max_targets": org.max_targets,
                    "max_scans_per_day": org.max_scans_per_day,
                    "stripe_subscription_id": org.stripe_subscription_id,
                    "stripe_customer_id": org.stripe_customer_id,
                    "created_at": org.created_at.isoformat(),
                    "updated_at": org.updated_at.isoformat()
                }
            },
            "Subscription retrieved"
        )
    
    except Exception as e:
        logger.error(f"Failed to get subscription: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to get subscription", 500)


# ==============================================================================
# CREATE/UPGRADE SUBSCRIPTION
# ==============================================================================

# ==============================================================================
# CREATE CHECKOUT SESSION — redirects to Stripe-hosted payment page
# ==============================================================================

@billing_bp.route("/checkout", methods=["POST"])
@jwt_required()
def create_checkout_session():
    """
    POST /api/billing/checkout

    Creates a Stripe Checkout Session and returns the URL to redirect the
    user to. Stripe hosts the actual payment form -- we never see or
    handle card details directly.

    CRITICAL: org.plan is NEVER updated here. This route only starts
    the payment flow. The plan is activated exclusively by the
    checkout.session.completed webhook, once Stripe confirms the
    payment actually succeeded. This prevents a user from setting
    their own plan by simply calling this endpoint with a fake
    payment_method_id (which was the bug in the previous version of
    this route).

    Request:
        { "plan": "pro" }  # starter | pro | enterprise (not "free")

    Response:
        200: { "data": { "checkout_url": "https://checkout.stripe.com/..." } }
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)

        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN, "Only organization admins can manage billing", 403
            )

        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)

        if not STRIPE_ENABLED:
            return error_response(
                ErrorCode.SERVICE_UNAVAILABLE, "Stripe integration not configured", 503
            )

        data = request.get_json()
        if not data or "plan" not in data:
            return error_response(ErrorCode.MISSING_FIELD, "plan field required", 400)

        plan = data["plan"].lower()
        price_id = current_app.config["STRIPE_PRICE_IDS"].get(plan)
        if not price_id:
            return error_response(
                ErrorCode.INVALID_ENUM,
                "plan must be one of: starter, pro, enterprise",
                400
            )

        # Ensure a Stripe Customer exists for this org before checkout
        if not org.stripe_customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={"org_id": org.id},
            )
            org.stripe_customer_id = customer.id
            db.session.commit()

        frontend_url = current_app.config.get("FRONTEND_URL", "http://localhost:3000")

        session = stripe.checkout.Session.create(
            customer=org.stripe_customer_id,
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=f"{frontend_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{frontend_url}/billing/cancel",
            metadata={"org_id": org.id, "plan": plan},
        )

        logger.info(f"Created Stripe Checkout session for org {org.id}, plan={plan}")

        return success_response({"checkout_url": session.url}, "Checkout session created")

    except stripe.error.StripeError as e:
        logger.error(f"Stripe checkout session creation failed: {e}")
        return error_response(ErrorCode.EXTERNAL_SERVICE_ERROR, "Stripe error", 503)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to create checkout session: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to create checkout session", 500)


# ==============================================================================
# CANCEL SUBSCRIPTION
# ==============================================================================

@billing_bp.route("/subscription", methods=["DELETE"])
@jwt_required()
def cancel_subscription():
    """
    DELETE /api/billing/subscription
    
    Cancel subscription and downgrade to FREE plan.
    Only admins can cancel. Cannot be undone immediately.
    
    Response:
        200: {"success": true, "data": {"subscription": {...}}}
    """
    try:
        user = get_current_user()
        if not user:
            return error_response(ErrorCode.NOT_FOUND, "User not found", 404)
        
        if not is_admin(user):
            return error_response(
                ErrorCode.FORBIDDEN,
                "Only organization admins can cancel subscription",
                403
            )
        
        org = user.organization
        if not org or org.is_deleted:
            return error_response(ErrorCode.NOT_FOUND, "Organization not found", 404)
        
        if org.plan == "free":
            return error_response(
                ErrorCode.CONFLICT,
                "Organization is already on free plan",
                409
            )
        
        old_plan = org.plan
        
        # Cancel Stripe subscription if exists
        if org.stripe_subscription_id and STRIPE_ENABLED:
            try:
                stripe.Subscription.delete(org.stripe_subscription_id)
            except stripe.error.StripeError as e:
                logger.error(f"Stripe cancellation failed: {e}")
                return error_response(
                    ErrorCode.EXTERNAL_SERVICE_ERROR,
                    "Failed to cancel Stripe subscription",
                    503
                )
        
        # Downgrade to free plan
        org.plan = "free"
        org.subscription_status = "canceled"
        org.stripe_subscription_id = None
        
        # Reset to free plan limits
        free_plan = PLANS["free"]
        org.max_members = free_plan["max_members"]
        org.max_targets = free_plan["max_targets"]
        org.max_scans_per_day = free_plan["scans_per_day"]
        
        db.session.commit()
        
        # Record event
        event = Event.record(
            organization_id=org.id,
            entity_type=EntityType.ORGANIZATION,
            entity_id=org.id,
            event_type=EventType.ORG_PLAN_CHANGED,
            actor_id=user.id,
            source=EventSource.USER,
            payload={
                "action": "plan_canceled",
                "from": old_plan,
                "to": "free"
            }
        )
        db.session.add(event)
        db.session.commit()
        
        logger.info(f"Organization {org.id} downgraded from {old_plan} to free")
        
        return success_response(
            {
                "subscription": {
                    "plan": org.plan,
                    "plan_name": "Free",
                    "status": org.subscription_status,
                    "max_members": org.max_members,
                    "max_targets": org.max_targets,
                    "max_scans_per_day": org.max_scans_per_day,
                    "created_at": org.created_at.isoformat(),
                    "updated_at": org.updated_at.isoformat()
                }
            },
            "Subscription canceled - downgraded to free plan"
        )
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to cancel subscription: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to cancel subscription", 500)


# ==============================================================================
# GET INVOICES
# ==============================================================================

@billing_bp.route("/invoices", methods=["GET"])
@jwt_required()
def list_invoices():
    """
    GET /api/billing/invoices
    
    List all invoices for organization's Stripe subscription.
    Requires Stripe integration.
    
    Response:
        200: {
            "success": true,
            "data": {
                "invoices": [
                    {
                        "id": "in_...",
                        "amount": 9900,
                        "currency": "usd",
                        "status": "paid",
                        "date": "2026-06-18T...",
                        "pdf_url": "https://..."
                    },
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
        
        if not org.stripe_customer_id:
            return success_response(
                {"invoices": []},
                "No invoices found"
            )
        
        if not STRIPE_ENABLED:
            return error_response(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Stripe integration not configured",
                503
            )
        
        try:
            invoices = stripe.Invoice.list(customer=org.stripe_customer_id, limit=50)
            
            invoices_list = []
            for invoice in invoices.data:
                invoices_list.append({
                    "id": invoice.id,
                    "amount": invoice.amount_due,
                    "currency": invoice.currency.upper(),
                    "status": invoice.status,
                    "date": invoice.created,
                    "pdf_url": invoice.invoice_pdf
                })
            
            return success_response(
                {"invoices": invoices_list},
                "Invoices retrieved"
            )
        
        except stripe.error.StripeError as e:
            logger.error(f"Failed to fetch invoices from Stripe: {e}")
            return error_response(
                ErrorCode.EXTERNAL_SERVICE_ERROR,
                "Failed to fetch invoices",
                503
            )
    
    except Exception as e:
        logger.error(f"Failed to list invoices: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list invoices", 500)


# ==============================================================================
# STRIPE WEBHOOK HANDLER
# ==============================================================================

@billing_bp.route("/webhook/stripe", methods=["POST"])
def handle_stripe_webhook():
    """
    POST /api/billing/webhook/stripe
    
    Handle Stripe webhook events (internal use only).
    Verifies Stripe signature before processing.
    
    Supported events:
        - customer.subscription.updated
        - customer.subscription.deleted
        - invoice.payment_succeeded
        - invoice.payment_failed
        - charge.refunded
    
    Note: This endpoint is NOT JWT protected - it receives direct webhooks from Stripe.
    Security: We verify the Stripe signature using the webhook secret.
    """
    try:
        if not STRIPE_ENABLED:
            return error_response(
                ErrorCode.SERVICE_UNAVAILABLE,
                "Stripe integration not configured",
                503
            )
        
        payload = request.get_data(as_text=True)
        sig_header = request.headers.get("Stripe-Signature")
        
        if not sig_header:
            logger.warning("Stripe webhook received without signature")
            return error_response(ErrorCode.UNAUTHORIZED, "Missing signature", 401)
        
        # Verify signature
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            logger.warning("Stripe webhook signature verification failed")
            return error_response(ErrorCode.UNAUTHORIZED, "Invalid signature", 401)
        except stripe.error.SignatureVerificationError:
            logger.warning("Stripe webhook signature verification failed")
            return error_response(ErrorCode.UNAUTHORIZED, "Signature verification failed", 401)
        
        # Handle events
        event_type = event["type"]
        event_data = event["data"]["object"].to_dict()
        
        logger.info(f"Processing Stripe webhook: {event_type}")
        
        if event_type == "checkout.session.completed":
            org_id = event_data.get("metadata", {}).get("org_id")
            plan = event_data.get("metadata", {}).get("plan")
            subscription_id = event_data.get("subscription")

            org = Organization.query.get(org_id) if org_id else None

            if org and plan:
                org.plan = plan
                org.subscription_status = "active"
                org.stripe_subscription_id = subscription_id

                plan_info = PLANS.get(plan, PLANS["free"])
                org.max_members = plan_info["max_members"]
                org.max_targets = plan_info["max_targets"]
                org.max_scans_per_day = plan_info["scans_per_day"]

                db.session.commit()

                event_record = Event.record(
                    organization_id=org.id,
                    entity_type=EntityType.ORGANIZATION,
                    entity_id=org.id,
                    event_type=EventType.ORG_PLAN_CHANGED,
                    source=EventSource.SYSTEM,
                    payload={"action": "plan_activated", "plan": plan, "subscription_id": subscription_id}
                )
                db.session.add(event_record)
                db.session.commit()
                logger.info(f"Activated plan {plan} for org {org.id} via checkout webhook")
        
        # Handle subscription events
        if event_type == "customer.subscription.updated":
            customer_id = event_data.get("customer")
            org = Organization.query.filter_by(stripe_customer_id=customer_id).first()
            
            if org:
                org.subscription_status = event_data.get("status", "active")
                db.session.commit()
                logger.info(f"Updated subscription status for org {org.id}")
        
        elif event_type == "customer.subscription.deleted":
            customer_id = event_data.get("customer")
            org = Organization.query.filter_by(stripe_customer_id=customer_id).first()
            
            if org:
                org.subscription_status = "canceled"
                org.plan = "free"
                org.stripe_subscription_id = None
                db.session.commit()
                logger.info(f"Canceled subscription for org {org.id}")
        
        elif event_type == "invoice.payment_succeeded":
            customer_id = event_data.get("customer")
            org = Organization.query.filter_by(stripe_customer_id=customer_id).first()
            
            if org:
                org.subscription_status = "active"
                
                # Record event
                event_record = Event.record(
                    organization_id=org.id,
                    entity_type=EntityType.ORGANIZATION,
                    entity_id=org.id,
                    event_type=EventType.OTHER,
                    source=EventSource.SYSTEM,
                    payload={
                        "action": "payment_received",
                        "amount": event_data.get("amount_paid"),
                        "currency": event_data.get("currency")
                    }
                )
                db.session.add(event_record)
                db.session.commit()
                logger.info(f"Payment received for org {org.id}")
        
        elif event_type == "invoice.payment_failed":
            customer_id = event_data.get("customer")
            org = Organization.query.filter_by(stripe_customer_id=customer_id).first()
            
            if org:
                org.subscription_status = "past_due"
                
                # Record event
                event_record = Event.record(
                    organization_id=org.id,
                    entity_type=EntityType.ORGANIZATION,
                    entity_id=org.id,
                    event_type=EventType.OTHER,
                    source=EventSource.SYSTEM,
                    payload={
                        "action": "payment_failed",
                        "amount": event_data.get("amount_due"),
                        "currency": event_data.get("currency")
                    }
                )
                db.session.add(event_record)
                db.session.commit()
                logger.warning(f"Payment failed for org {org.id}")
                
                # TODO: Send email notification to admin
        
        return success_response(None, "Webhook processed")
    
    except Exception as e:
        logger.error(f"Failed to handle Stripe webhook: {e}", exc_info=True)
        # Always return 200 to Stripe so it doesn't retry
        return success_response(None, "Webhook processed")


# ==============================================================================
# PAYMENT METHODS (for future use)
# ==============================================================================

@billing_bp.route("/payment-methods", methods=["GET"])
@jwt_required()
def list_payment_methods():
    """
    GET /api/billing/payment-methods
    
    List payment methods on file for organization.
    Requires Stripe integration.
    
    Response:
        200: {
            "success": true,
            "data": {
                "payment_methods": [
                    {
                        "id": "pm_...",
                        "type": "card",
                        "last4": "4242",
                        "brand": "visa",
                        "exp_month": 12,
                        "exp_year": 2026
                    },
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
        
        if not org.stripe_customer_id or not STRIPE_ENABLED:
            return success_response(
                {"payment_methods": []},
                "No payment methods found"
            )
        
        try:
            payment_methods = stripe.PaymentMethod.list(
                customer=org.stripe_customer_id,
                type="card"
            )
            
            methods_list = []
            for pm in payment_methods.data:
                methods_list.append({
                    "id": pm.id,
                    "type": pm.type,
                    "last4": pm.card.last4,
                    "brand": pm.card.brand.upper(),
                    "exp_month": pm.card.exp_month,
                    "exp_year": pm.card.exp_year
                })
            
            return success_response(
                {"payment_methods": methods_list},
                "Payment methods retrieved"
            )
        
        except stripe.error.StripeError as e:
            logger.error(f"Failed to fetch payment methods: {e}")
            return error_response(
                ErrorCode.EXTERNAL_SERVICE_ERROR,
                "Failed to fetch payment methods",
                503
            )
    
    except Exception as e:
        logger.error(f"Failed to list payment methods: {e}", exc_info=True)
        return error_response(ErrorCode.INTERNAL_ERROR, "Failed to list payment methods", 500)