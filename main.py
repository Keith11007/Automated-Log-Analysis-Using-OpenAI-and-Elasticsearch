""" Starts flask development server.
"""

from __future__ import annotations

import os

from app_factory import create_app


app = create_app()


if __name__ == "__main__":
   
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "8000"))
    app.run(debug=True, host=host, port=port)
