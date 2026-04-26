"""
Shared error collector for scanner modules.
"""

from datetime import datetime
from typing import Any, Dict, List


class ModuleErrorCollector:
    """Collects structured module errors in a consistent format."""

    def __init__(self, module_name: str):
        self.module_name = module_name
        self._errors: List[Dict[str, Any]] = []

    def add(self, url: str, error: Exception | str, phase: str) -> None:
        self._errors.append(
            {
                "module": self.module_name,
                "phase": phase,
                "url": url,
                "error": str(error),
                "timestamp": datetime.now().isoformat(),
            }
        )

    def all(self) -> List[Dict[str, Any]]:
        return list(self._errors)

    def clear(self) -> None:
        self._errors.clear()
