"""Scanner engine — stub for Session 3."""

from agentsec.adapters.base import AbstractAdapter
from agentsec.core.config import ScanConfig


class Scanner:
    """Core scan orchestrator. Full implementation in Session 3."""

    def __init__(self, adapter: AbstractAdapter, config: ScanConfig):
        self.adapter = adapter
        self.config = config
