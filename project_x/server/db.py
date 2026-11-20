"""Engine and session lifecycle. Never creates schemas implicitly."""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker


def engine_for(url: str):
    if url.startswith("sqlite:"):
        engine = create_engine(url, connect_args={"check_same_thread": False})

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=10000")
            cursor.close()

        return engine
    return create_engine(url, pool_pre_ping=True)


def sessions_for(engine):
    return sessionmaker(engine, expire_on_commit=False, autoflush=False)
