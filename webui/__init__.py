"""
Web UI package for the Webhook Security Scanner.

This package exposes a FastAPI application via `app` and an app factory `create_app`.
"""

from .app import create_app, app 
