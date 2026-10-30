"""
Production-ready Celery configuration.

This module exposes a SINGLE global Celery instance used by:
  - Flask routes  : celery.send_task("scanner.run_scan", args=[...])
  - Celery worker : python -m celery -A celery_app:celery worker
  - scanner.py    : from celery_app import celery

ROOT CAUSE OF "Working outside of application context":
  The worker loads celery_app.py directly (via -A celery_app:celery).
  It never calls create_app(), so init_celery(app) was never executed,
  meaning ContextTask was never installed.

FIX:
  celery_app.py now calls create_app() itself when the module is loaded
  BY THE WORKER PROCESS. This guarantees the Flask app context is always
  available to tasks, whether the Celery instance is used by the Flask
  server (which already calls init_celery() itself from create_app())
  or by a standalone worker.

FIX 2 (this revision):
  The original version called _bootstrap_worker_context() unconditionally
  at module import time. That meant EVERY import of celery_app.py -- 
  including the one that happens when Flask's own create_app() does
  `from celery_app import celery` -- constructed a second, independent
  Flask app (its own SQLAlchemy engine, its own connection pool, its own
  blueprint registrations) purely as a side effect of the import. That
  second app was then just discarded, but not before doing real work
  (DB engine creation, extension init) that Flask's real app already
  does. Under load this risks connection-pool exhaustion and, in the
  worst case, a circular create_app() call if this module is imported
  partway through Flask's own startup.

  The fix is to only run the bootstrap when this module is loaded by the
  actual Celery worker process, not by Flask. We gate it behind a
  CELERY_WORKER env var that must be set explicitly when launching the
  worker:

      CELERY_WORKER=1 celery -A celery_app:celery worker --loglevel=info

  Flask's own process should NOT set this env var, so importing
  celery_app.py from create_app() is now a no-op beyond building the
  Celery instance itself.
"""

import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CELERY INSTANCE
# ==============================================================================

celery = Celery(
    "scanner",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
)

celery.conf.update(
    broker_url=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    result_backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),

    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    timezone="UTC",
    enable_utc=True,

    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,

    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,

    result_expires=3600,
    broker_connection_retry_on_startup=True,
)

celery.autodiscover_tasks(["app"], related_name="tasks")


# ==============================================================================
# FLASK APP CONTEXT — FIX
# ==============================================================================
# Binds every Celery task to a Flask application context so db.session and
# all models work normally inside tasks.
# ==============================================================================

def init_celery(app):
    """
    Bind every Celery task to the Flask application context.

    Called from create_app() in app/__init__.py:
        from celery_app import init_celery
        init_celery(app)

    Also called below, but ONLY when this module is loaded by the actual
    Celery worker process (see CELERY_WORKER guard at the bottom of this
    file) -- not when Flask itself imports this module.
    """

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


# ==============================================================================
# AUTO-INITIALIZE — ONLY for the Celery worker process
# ==============================================================================
# When the worker runs:
#   CELERY_WORKER=1 celery -A celery_app:celery worker
#
# It imports this module directly and never calls create_app() itself, so
# we bootstrap a Flask app here and bind it via init_celery(). This must
# NOT happen when Flask imports this module (e.g. via
# `from celery_app import celery` inside create_app() or scanner.py),
# because Flask already has its own app instance and calling create_app()
# again here would build a redundant one (duplicate DB engine/connection
# pool) or risk recursing into Flask's own not-yet-finished startup.
#
# Set CELERY_WORKER=1 in the environment you launch the worker with, and
# leave it unset everywhere else (Flask server, tests, scripts).
# ==============================================================================

def _bootstrap_worker_context():
    """
    Create a Flask app and bind it to Celery tasks.
    Only called when CELERY_WORKER=1 is set in the environment -- i.e.
    when this module is loaded by the actual Celery worker process.
    """
    try:
        # Import here to avoid circular imports
        from app import create_app
        flask_app = create_app(
            os.getenv("FLASK_ENV", "development")
        )
        init_celery(flask_app)
    except Exception as e:
        # Don't crash if Flask app can't be created
        # (e.g. during testing or partial imports)
        import logging
        logging.getLogger("bug_bounty").warning(
            f"celery_app: could not bootstrap Flask context: {e}"
        )


if os.getenv("CELERY_WORKER") == "1":
    _bootstrap_worker_context()