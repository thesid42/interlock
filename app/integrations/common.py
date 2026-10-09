"""Explicit provider state without exposing credentials or response bodies."""

from dataclasses import dataclass


class IntegrationError(RuntimeError):
    pass


class IntegrationUnavailable(IntegrationError):
    pass


@dataclass(frozen=True)
class ProviderState:
    provider: str
    configured: bool
    verified: bool = False
    detail: str = "Not configured"

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "configured": self.configured,
            "verified": self.verified,
            "detail": self.detail,
        }
