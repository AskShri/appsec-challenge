"""
Application entry point.

Usage:
    python run.py

Starts the Flask development server on http://localhost:5000.
Demo credentials: demo@xero.com / SecureP@ss123!
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    print('\n  Secure Login Portal')
    print('  ===================')
    print('  Demo credentials: demo@xero.com / SecureP@ss123!')
    print('  URL: http://localhost:5000\n')

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
    )
