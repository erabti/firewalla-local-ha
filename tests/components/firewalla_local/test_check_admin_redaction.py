"""Tests for the live-response redaction check."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType

import pytest

_TOOL_PATH = Path(__file__).parents[3] / "utils" / "check_admin_redaction.py"
_WIFI_KEY = "made-up-wifi-password"
_NEW_SECRET = "made-up-secret-in-a-new-field"


def _load_tool() -> ModuleType:
    """Load the check from its file, as running it does."""
    spec = importlib.util.spec_from_file_location("check_admin_redaction", _TOOL_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Loaded while tests are collected: inside a test, Home Assistant's test setup
# has already pointed ``custom_components`` at its own folder.
_TOOL = _load_tool()


def _config() -> dict[str, object]:
    """Return a made-up config in the router's layout."""
    return {
        "apc": {
            "assets": {"20:6D:31:00:00:01": {"publicKey": "made-up-public-key"}},
            "profile": {
                "0d6f2c1e-0000-4000-8000-000000000001": {
                    "ssid": "Example Home",
                    "key": _WIFI_KEY,
                }
            },
        },
        "nat_passthrough": {},
    }


def test_check_passes_when_every_secret_is_hidden(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A config whose secrets are all hidden passes, and names the hidden field."""
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_config())))

    assert _TOOL.main() == 0

    output = capsys.readouterr().out
    assert "apc.profile.<id>.key" in output
    assert _WIFI_KEY not in output


def test_check_fails_on_a_readable_field_with_a_secret_looking_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A new firmware field the rule does not hide fails the check by name."""
    config = _config()
    config["radius"] = [{"sharedKeyValue": _NEW_SECRET}]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(config)))

    assert _TOOL.main() == 1

    output = capsys.readouterr().out
    assert "radius[].sharedKeyValue" in output
    assert _NEW_SECRET not in output
