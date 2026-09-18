"""Base class for all detection rules."""


from backend.models.events import OCSFBaseEvent

class BaseRule:
    name: str = "base_rule"
    description: str = ""

    async def evaluate(self, log: OCSFBaseEvent, windows: dict) -> dict | None:
        """Return a match dict if triggered, else None."""
        raise NotImplementedError
