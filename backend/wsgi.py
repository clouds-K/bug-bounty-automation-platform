"""
Production entry point (Gunicorn)
"""

import os
from app import create_app

config_name = os.getenv("FLASK_ENV", "production")
app = create_app(config_name)

# Gunicorn entrypoint
application = app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)