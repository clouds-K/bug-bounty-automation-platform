"""
Routes package - Central registry for all blueprints
"""


from app.routes.auth import auth_bp
from app.routes.target import target_bp
from app.routes.vulnerability import vuln_bp
from app.routes.scan import scan_bp
from app.routes.bounty import bounty_bp

__all__ = ["auth_bp", "target_bp", "vuln_bp", "scan_bp","bounty_bp"]