"""Smart-contract security engines (local, static, synthetic-fixture validated). Emits engines.contract.EngineFinding;
never CONFIRMED."""
from .engine import ENGINE, run, scan

__all__ = ["ENGINE", "run", "scan"]
