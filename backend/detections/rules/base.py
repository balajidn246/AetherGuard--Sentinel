"""Base class for all detection rules."""


class BaseRule:
    name: str = "base_rule"
    description: str = ""

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        """Return a match dict if triggered, else None."""
        raise NotImplementedError
