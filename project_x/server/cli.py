"""Offline administrative bootstrap. Never pass generated tokens on command lines."""
import argparse
import getpass
from sqlalchemy.orm import Session
from .config import Settings
from .db import engine_for
from .models import ApiToken
from .security import fingerprint, new_secret


def main():
    parser = argparse.ArgumentParser(description="Issue or revoke an administrator bearer token (offline)")
    parser.add_argument("command", choices=["bootstrap-admin", "revoke-token"])
    args = parser.parse_args()
    cfg = Settings.from_env()
    engine = engine_for(cfg.database_url)
    with Session(engine) as db:
        if args.command == "bootstrap-admin":
            token = new_secret()
            record = ApiToken(token_hash=fingerprint(cfg.token_pepper, token), role="admin")
            db.add(record)
            db.commit()
            print("Administrator bearer token (displayed once):")
            print(token)
            print("Token ID:", record.id)
        else:
            print("Enter administrator token to revoke (no echo):")
            raw = getpass.getpass()
            record = db.query(ApiToken).filter_by(token_hash=fingerprint(cfg.token_pepper, raw)).one_or_none()
            if record is None:
                raise SystemExit("Token not found")
            from datetime import datetime, timezone
            record.revoked_at = datetime.now(timezone.utc)
            db.commit()
            print("Token revoked")


if __name__ == "__main__":
    main()
