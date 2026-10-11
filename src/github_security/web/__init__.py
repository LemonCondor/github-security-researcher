"""Passive web security analysis engine (web.passive/2): offline, capture-based, no network I/O."""
from .engine import ENGINE, analyze, render_text, run

__all__ = ["ENGINE", "analyze", "render_text", "run"]
