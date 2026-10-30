"""
Production-ready configuration
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base config"""

    # ==========================
    # SECURITY
    # ==========================
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-key")
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET") 
    STRIPE_PRICE_IDS = {
    "starter": os.getenv("STRIPE_PRICE_STARTER"),
    "pro": os.getenv("STRIPE_PRICE_PRO"),
    "enterprise": os.getenv("STRIPE_PRICE_ENTERPRISE"),
}
    
    # on le récupère à l'étape webhook
    # ==========================
    # DB
    # ==========================
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ==========================
    # JWT
    # ==========================
    
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_ACCESS_COOKIE_PATH = "/api/"
    JWT_REFRESH_COOKIE_PATH = "/api/auth/refresh"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_COOKIE_SECURE = True  # surchargé à False en dev, voir DevelopmentConfig
    

    # ==========================
    # CELERY
    # ==========================
    # NOTE: celery_app.py reads CELERY_BROKER_URL / CELERY_RESULT_BACKEND
    # directly via os.getenv(...) with its own fallbacks, NOT via this
    # Config class -- it must work even when imported outside a Flask
    # app context (e.g. by the standalone worker process before
    # create_app() runs). These two settings are kept here for reference
    # / potential future use (e.g. admin dashboards reading app.config),
    # but changing them alone will NOT change what celery_app.py connects
    # to -- update your env vars instead.
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND")

    # ==========================================================================
    # SCANNER — Nuclei Docker execution
    # --------------------------------------------------------------------------
    # Consumed by scanner.py's run_nuclei() via current_app.config (the
    # Celery task runs inside a Flask app context, so this is available).
    # Lets you change the scan image or per-scan resource caps via env
    # vars / this file without touching scanner.py or redeploying code.
    # Defaults match what was previously hardcoded in scanner.py.
    # ==========================================================================
    NUCLEI_DOCKER_IMAGE = os.getenv("NUCLEI_DOCKER_IMAGE", "projectdiscovery/nuclei:latest")
    NUCLEI_HTTP_TIMEOUT_SECONDS = int(os.getenv("NUCLEI_HTTP_TIMEOUT_SECONDS", 10))

    # Name of the persistent Docker volume holding the pre-populated
    # nuclei-templates catalog (created once via `git clone`, refreshed
    # periodically out-of-band -- see ops runbook). Mounted read-only
    # into every scan container so scans never hit GitHub's API rate
    # limit and never run with zero templates loaded.
    NUCLEI_TEMPLATES_VOLUME = os.getenv("NUCLEI_TEMPLATES_VOLUME", "nuclei-templates")
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    NVD_API_BASE_URL = os.getenv("NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    # Per-scan container memory cap, Docker mem_limit format (e.g. "512m", "1g")
    SCAN_CONTAINER_MEM_LIMIT = os.getenv("SCAN_CONTAINER_MEM_LIMIT", "1536m")

    # Per-scan container CPU cap, in nano-CPUs (1_000_000_000 == 1 full core)
    SCAN_CONTAINER_NANO_CPUS = int(os.getenv("SCAN_CONTAINER_NANO_CPUS", 1_000_000_000))

    # Extra seconds added on top of (timeout_minutes * 60) as a safety
    # buffer for container startup before we consider a scan container hung
    SCAN_CONTAINER_TIMEOUT_BUFFER_SECONDS = int(
        os.getenv("SCAN_CONTAINER_TIMEOUT_BUFFER_SECONDS", 120)
    )

    # ==========================
    # CORS
    # ==========================
    CORS_ORIGINS = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "").split(",")
        if o.strip()
    ]
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://192.168.56.104:5173")


class DevelopmentConfig(Config):
    DEBUG = True
    JWT_COOKIE_SECURE = False  # pas de HTTPS en local
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://bounty_user:secure_password@localhost:5432/bug_bounty_db"
    )


class TestingConfig(Config):
    TESTING = True
    PROPAGATE_EXCEPTIONS = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")

    # ==========================
    # PRODUCTION SECURITY HARDENING
    # ==========================
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}