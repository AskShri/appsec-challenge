"""
Authentication blueprint — handles login, logout, and dashboard routes.
"""

from flask import Blueprint

auth_bp = Blueprint(
    'auth',
    __name__,
    template_folder='../templates',
)

# Import routes to register them with the blueprint.
# This import must be at the bottom to avoid circular imports.
from app.auth import routes  # noqa: E402, F401
