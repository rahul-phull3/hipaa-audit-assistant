"""HTTP API (Starlette) over the audit service."""

from hipaa_audit.api.app import create_app

__all__ = ["create_app"]
