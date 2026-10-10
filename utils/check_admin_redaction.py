"""Check that admin redaction hides every secret-looking field of a real response.

Reads one Firewalla JSON response on stdin, such as the live network config,
and prints field names only, never a value:

    ssh firewalla 'curl -s http://localhost:8837/v1/config/active' \
        | .venv/bin/python utils/check_admin_redaction.py

Exits 1 when a field that stays readable has a name that could hold a secret.
Then teach ``_is_sensitive_key`` the name, or add it to ``_PLAIN_NAMES`` here
when it is not a secret.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Final

# Check this checkout's code, not an installed copy of the integration.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.firewalla_local.managers.admin_manager import (
    _REDACTED_VALUE,
    _redact_sensitive,
)

_SUSPECT_NAME: Final = re.compile(r"(?i)key|psk|pass|secret|token|credential")
_PUBLIC_KEY_NAME: Final = re.compile(r"(?i)pub(lic)?_?keys?$")
_PLAIN_NAMES: Final[frozenset[str]] = frozenset()
_ID_NAME: Final = re.compile(
    r"(?i)^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2})$"
)


def find_fields(raw: object) -> tuple[list[str], list[str]]:
    """Return the paths of the hidden fields and of the readable suspect ones."""
    hidden: set[str] = set()
    suspect: set[str] = set()

    def walk(value: object, redacted: object, path: str, name: str) -> None:
        if redacted == _REDACTED_VALUE:
            hidden.add(path)
        elif isinstance(value, dict) and isinstance(redacted, dict):
            for key, nested in value.items():
                shown = "<id>" if _ID_NAME.match(str(key)) else str(key)
                walk(
                    nested,
                    redacted[str(key)],
                    f"{path}.{shown}" if path else shown,
                    str(key),
                )
        elif isinstance(value, list) and isinstance(redacted, list):
            for nested, nested_redacted in zip(value, redacted, strict=True):
                walk(nested, nested_redacted, f"{path}[]", name)
        elif (
            _SUSPECT_NAME.search(name)
            and not _PUBLIC_KEY_NAME.search(name)
            and name not in _PLAIN_NAMES
        ):
            suspect.add(path)

    walk(raw, _redact_sensitive(raw), "", "")
    return sorted(hidden), sorted(suspect)


def main() -> int:
    """Print the hidden and the suspect field names of the response on stdin."""
    try:
        raw = json.load(sys.stdin)
    except ValueError:
        print("stdin is not JSON")
        return 2
    hidden, suspect = find_fields(raw)
    print(f"hidden fields: {len(hidden)}")
    for path in hidden:
        print(f"  {path}")
    print(f"readable fields with a secret-looking name: {len(suspect)}")
    for path in suspect:
        print(f"  {path}")
    return 1 if suspect else 0


if __name__ == "__main__":
    raise SystemExit(main())
