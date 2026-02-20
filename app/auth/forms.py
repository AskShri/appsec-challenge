"""
WTForms form definitions with input validation.

Server-side validation is the authoritative check — client-side HTML5
validation is a UX convenience only (easily bypassed).

Input constraints:
- Email: Required, valid format, max 254 chars (RFC 5321 §4.5.3.1.3)
- Password: Required, max 128 chars (prevents bcrypt DoS via huge inputs)
"""

from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField
from wtforms.validators import DataRequired, Email, Length


class LoginForm(FlaskForm):
    """Login form with email and password validation."""

    email = EmailField(
        'Email address',
        validators=[
            DataRequired(message='Email address is required.'),
            Email(message='Please enter a valid email address.'),
            # RFC 5321 limits the total email address to 254 characters.
            Length(max=254, message='Email address is too long.'),
        ],
        render_kw={
            'placeholder': 'e.g., jane.doe@example.com',
            'autofocus': True,
            'autocomplete': 'email',
        },
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            # Max 128 chars: bcrypt truncates at 72 bytes (we pre-hash with SHA-256),
            # but we still bound input size to prevent memory allocation attacks.
            Length(max=128, message='Password is too long.'),
        ],
        render_kw={
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password',
        },
    )
