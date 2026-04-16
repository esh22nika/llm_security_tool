"""
CineSage Dataset Manager
========================
Manages the runtime movie dataset with hot-reload, reset, and attack-mode
switching — no server restart required.

Dataset files (relative to this module's directory):
  data/movies_clean.json     — sanitized baseline (shipped with the repo)
  data/movies_poisoned.json  — baseline + 3 pre-seeded POISON records
  data/movies.json           — active runtime file (overwritten by this module)

In-memory state lives in the module-level ``_state`` dict so every import
shares the same object. Call ``get_movies()`` anywhere in the app instead of
reading movies.json directly.
"""

from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path
from typing import Any

# ── Paths ──────────────────────────────────────────────────────────────────────
_BASE = Path(__file__).parent / "data"

ACTIVE_PATH   = _BASE / "movies.json"
CLEAN_PATH    = _BASE / "movies_clean.json"
POISONED_PATH = _BASE / "movies_poisoned.json"

# ── Shared mutable state ───────────────────────────────────────────────────────
_lock = threading.Lock()
_state: dict[str, Any] = {
    "movies":       [],   # live list used by retrieve_context()
    "mode":         "clean",   # "clean" | "poisoned"
    "reset_count":  0,
    "injected":     [],   # runtime records added via /api/inject-poison
}


# ── Internal helpers ───────────────────────────────────────────────────────────

def _read_json(path: Path) -> list[dict]:
    """Read and return a JSON array from *path*. Returns [] on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[dataset_manager] WARNING: could not read {path}: {exc}")
        return []


def _write_active(source: Path) -> None:
    """Atomically overwrite movies.json with *source*."""
    shutil.copy2(source, ACTIVE_PATH)


# ── Public API ─────────────────────────────────────────────────────────────────

def load_movies(force_reload: bool = False) -> list[dict]:
    """
    Return the current in-memory movie list.
    On first call (or when *force_reload* is True) the list is populated from
    movies.json (the active runtime file).
    """
    with _lock:
        if force_reload or not _state["movies"]:
            _state["movies"] = _read_json(ACTIVE_PATH)
        return list(_state["movies"])  # shallow copy — safe to iterate


def get_movies() -> list[dict]:
    """Shorthand used by retrieve_context()."""
    return load_movies()


def get_injected() -> list[dict]:
    """Return the list of records injected at runtime via the Poison Lab."""
    with _lock:
        return list(_state["injected"])


def add_injected(records: list[dict] | dict) -> None:
    """Append one or more runtime-injected records."""
    with _lock:
        if isinstance(records, dict):
            records = [records]
        _state["injected"].extend(records)


def clear_injected() -> int:
    """Remove all runtime-injected records. Returns count cleared."""
    with _lock:
        count = len(_state["injected"])
        _state["injected"].clear()
        return count


def reset_dataset() -> dict:
    """
    Restore the dataset to the sanitized clean baseline.

    Actions
    -------
    1. Copy movies_clean.json → movies.json  (persists across process restarts)
    2. Reload in-memory list from the freshly written file
    3. Clear all runtime-injected records
    4. Reset mode flag to "clean"

    Returns a status dict suitable for an API response.
    """
    with _lock:
        if not CLEAN_PATH.exists():
            return {
                "success":  False,
                "error":    f"Clean baseline not found at {CLEAN_PATH}",
                "mode":     _state["mode"],
            }

        _write_active(CLEAN_PATH)
        _state["movies"]   = _read_json(ACTIVE_PATH)
        _state["injected"] = []
        _state["mode"]     = "clean"
        _state["reset_count"] += 1

        return {
            "success":      True,
            "mode":         "clean",
            "movie_count":  len(_state["movies"]),
            "reset_count":  _state["reset_count"],
            "message":      (
                f"Dataset restored to clean baseline "
                f"({len(_state['movies'])} records). "
                "All injected records cleared."
            ),
        }


def enable_attack_mode() -> dict:
    """
    Switch the active dataset to the pre-poisoned version for demos.

    Actions
    -------
    1. Copy movies_poisoned.json → movies.json
    2. Reload in-memory list
    3. Clear runtime-injected records (fresh attack surface)
    4. Set mode flag to "poisoned"

    Returns a status dict suitable for an API response.
    """
    with _lock:
        if not POISONED_PATH.exists():
            return {
                "success": False,
                "error":   f"Poisoned dataset not found at {POISONED_PATH}",
                "mode":    _state["mode"],
            }

        _write_active(POISONED_PATH)
        _state["movies"]   = _read_json(ACTIVE_PATH)
        _state["injected"] = []
        _state["mode"]     = "poisoned"

        poison_ids = [
            r["id"] for r in _state["movies"]
            if str(r.get("id", "")).startswith("POISON")
        ]

        return {
            "success":      True,
            "mode":         "poisoned",
            "movie_count":  len(_state["movies"]),
            "poison_count": len(poison_ids),
            "poison_ids":   poison_ids,
            "message":      (
                f"Attack dataset activated "
                f"({len(_state['movies'])} records, "
                f"{len(poison_ids)} pre-seeded poison records)."
            ),
        }


def get_status() -> dict:
    """Return current dataset status (used by health-check endpoints)."""
    with _lock:
        return {
            "mode":            _state["mode"],
            "movie_count":     len(_state["movies"]),
            "injected_count":  len(_state["injected"]),
            "reset_count":     _state["reset_count"],
            "active_file":     str(ACTIVE_PATH),
        }


# ── Bootstrap on import ────────────────────────────────────────────────────────
# Ensure movies.json exists and the in-memory list is populated.
if not ACTIVE_PATH.exists() and CLEAN_PATH.exists():
    shutil.copy2(CLEAN_PATH, ACTIVE_PATH)

load_movies()   # warm cache