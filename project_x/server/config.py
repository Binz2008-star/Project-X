"""Explicit runtime settings; secrets must be injected by the deployment environment."""
from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    database_url: str
    code_pepper: str
    token_pepper: str
    allowed_durations: tuple[int, ...] = (30, 90)
    trial_days: int = 7
    activation_limit_per_minute: int = 10
    validation_limit_per_minute: int = 60

    def __post_init__(self):
        if not self.database_url.startswith(("sqlite://", "postgresql+psycopg://")):
            raise ValueError("DATABASE_URL must use sqlite or postgresql+psycopg")
        if len(self.code_pepper) < 32 or len(self.token_pepper) < 32:
            raise ValueError("Both token and code peppers must be at least 32 characters")
        if self.code_pepper == self.token_pepper:
            raise ValueError("Token and activation-code peppers must be distinct")
        if not self.allowed_durations or any(x < 1 or x > 3660 for x in self.allowed_durations):
            raise ValueError("Subscription durations must be within 1..3660 days")
        if len(set(self.allowed_durations)) != len(self.allowed_durations):
            raise ValueError("Duplicate subscription duration")
        if not (1 <= self.trial_days <= 30):
            raise ValueError("TRIAL_DAYS must be between 1 and 30")
        if self.activation_limit_per_minute < 1 or self.validation_limit_per_minute < 1:
            raise ValueError("Rate limits must be positive")

    @classmethod
    def from_env(cls):
        def required(name):
            value = os.environ.get(name)
            if not value:
                raise RuntimeError(f"Missing required environment variable: {name}")
            return value

        return cls(
            database_url=required("DATABASE_URL"),
            code_pepper=required("CODE_PEPPER"),
            token_pepper=required("TOKEN_PEPPER"),
            allowed_durations=tuple(int(s.strip()) for s in os.getenv("LICENSE_DURATIONS_DAYS", "30,90").split(",")),
            trial_days=int(os.getenv("TRIAL_DAYS", "7")),
            activation_limit_per_minute=int(os.getenv("ACTIVATION_LIMIT_PER_MINUTE", "10")),
            validation_limit_per_minute=int(os.getenv("VALIDATION_LIMIT_PER_MINUTE", "60")),
        )
