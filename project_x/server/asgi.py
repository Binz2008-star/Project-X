"""ASGI production entrypoint; rejects missing/weak environment secrets."""
from .api import create_app

app = create_app()
