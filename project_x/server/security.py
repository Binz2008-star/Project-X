"""Per-purpose HMAC token hashing and token-bucket identity helpers."""
import hashlib
import hmac
import secrets


def fingerprint(secret: str, plaintext: str) -> str:
    return hmac.new(secret.encode("utf-8"), plaintext.encode("utf-8"), hashlib.sha256).hexdigest()


def new_secret() -> str:
    return secrets.token_urlsafe(32)
