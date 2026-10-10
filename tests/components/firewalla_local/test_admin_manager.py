"""Tests for the guarded Firewalla admin manager."""

from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from custom_components.firewalla_local.managers.admin_manager import (
    FirewallaAdminManager,
)


def _manager(*, get_result: object = None) -> tuple[FirewallaAdminManager, AsyncMock]:
    """Return an admin manager with a mocked client and coordinator."""
    client = SimpleNamespace(
        async_get_item=AsyncMock(return_value=get_result),
        async_set_item=AsyncMock(return_value={"ok": True}),
        async_command_item=AsyncMock(return_value={"ok": True}),
    )
    coordinator = SimpleNamespace(async_request_refresh=AsyncMock())
    manager = FirewallaAdminManager(coordinator, SimpleNamespace(), client)
    return manager, client


_WG_PRIVATE_KEY = "made-up-wireguard-private-key"
_WG_PRESHARED_KEY = "made-up-wireguard-preshared-key"
_WIFI_KEY = "made-up-wifi-password"
_MESH_KEY = "made-up-mesh-key"
_SECRETS = (_WG_PRIVATE_KEY, _WG_PRESHARED_KEY, _WIFI_KEY, _MESH_KEY)


def _network_config() -> dict[str, Any]:
    """Return a made-up network config in the router's layout."""
    return {
        "ncid": "current",
        "nat_passthrough": {},
        "interface": {
            "wireguard": {
                "wg0": {
                    "listenPort": 51820,
                    "privateKey": _WG_PRIVATE_KEY,
                    "peers": [
                        {
                            "publicKey": "made-up-peer-public-key",
                            "presharedKey": _WG_PRESHARED_KEY,
                            "allowedIPs": ["10.9.0.2/32"],
                        }
                    ],
                }
            }
        },
        "apc": {
            "assets": {"ap-1": {"publicKey": "made-up-ap-public-key"}},
            "assets_template": {
                "ap_default": {
                    "mesh": {
                        "ssid": "example-mesh",
                        "encryption": "sae",
                        "key": _MESH_KEY,
                    }
                }
            },
            "profile": {
                "profile-1": {
                    "ssid": "Example Home",
                    "band": "5g",
                    "encryption": "psk2",
                    "wpa3": False,
                    "key": _WIFI_KEY,
                }
            },
        },
    }


def _redacted_network_config() -> dict[str, Any]:
    """Return the made-up config as a caller should see it."""
    config = _network_config()
    wg0 = config["interface"]["wireguard"]["wg0"]
    wg0["privateKey"] = "[redacted]"
    wg0["peers"][0]["presharedKey"] = "[redacted]"
    config["apc"]["assets_template"]["ap_default"]["mesh"]["key"] = "[redacted]"
    config["apc"]["profile"]["profile-1"]["key"] = "[redacted]"
    return config


@pytest.mark.asyncio
async def test_admin_read_redacts_sensitive_fields() -> None:
    """Admin reads keep structure while removing returned credentials."""
    manager, client = _manager(
        get_result={"profileId": "wg0", "password": "secret", "nested": {"token": "x"}}
    )

    response = await manager.async_read("vpnProfiles")

    assert response["result"] == {
        "profileId": "wg0",
        "password": "[redacted]",
        "nested": {"token": "[redacted]"},
    }
    client.async_get_item.assert_awaited_once_with(
        "vpnProfiles", value=None, target="0.0.0.0"
    )


@pytest.mark.asyncio
async def test_admin_execute_defaults_to_dry_run() -> None:
    """A write request does not execute unless dry run is disabled."""
    manager, client = _manager()

    response = await manager.async_execute(
        "tag:create",
        value={"name": "Guests"},
    )

    assert response["executed"] is False
    client.async_command_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_execute_requires_confirmation() -> None:
    """A non-dry write requires explicit confirmation."""
    manager, client = _manager()

    with pytest.raises(ValueError, match="confirm must be true"):
        await manager.async_execute(
            "tag:create",
            value={"name": "Guests"},
            dry_run=False,
        )

    client.async_command_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_execute_routes_confirmed_command_and_refreshes() -> None:
    """A confirmed command reaches the command transport and refreshes."""
    manager, client = _manager()

    response = await manager.async_execute(
        "tag:create",
        value={"name": "Guests"},
        dry_run=False,
        confirm=True,
    )

    assert response["executed"] is True
    assert response["refreshed"] is True
    client.async_command_item.assert_awaited_once_with(
        "tag:create",
        value={"name": "Guests"},
        target="0.0.0.0",
    )


@pytest.mark.asyncio
async def test_network_config_dry_run_runs_impact_check() -> None:
    """Network dry runs merge patches without dropping hidden current values."""
    current = {
        "ncid": "current",
        "interface": {"wan": {"enabled": True, "password": "hidden"}},
    }
    manager, client = _manager(get_result=current)
    requested = {"ncid": "next", "interface": {"wan": {"enabled": False}}}
    merged = {
        "ncid": "next",
        "interface": {"wan": {"enabled": False, "password": "hidden"}},
    }

    response = await manager.async_execute("networkConfig", value=requested)

    assert response["executed"] is False
    assert response["network_config_mode"] == "merge_patch"
    assert isinstance(response["current_config_hash"], str)
    assert client.async_get_item.await_count == 2
    assert client.async_get_item.await_args_list[1].kwargs == {
        "value": {"config": merged}
    }
    client.async_set_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_config_rejects_stale_hash() -> None:
    """Network execution refuses a config changed since the caller read it."""
    manager, client = _manager(get_result={"ncid": "current"})

    with pytest.raises(ValueError, match="changed after it was read"):
        await manager.async_execute(
            "networkConfig",
            value={"ncid": "next"},
            dry_run=False,
            confirm=True,
            expected_current_hash="stale",
        )

    client.async_set_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_config_executes_with_matching_hash() -> None:
    """Network execution sends the merged config after hash and impact gates."""
    current = {
        "ncid": "current",
        "secretToken": "hidden",
        "interface": {"lan": {"enabled": True}},
    }
    manager, client = _manager(get_result=current)
    read_response = await manager.async_read("networkConfig")
    client.async_get_item.reset_mock()

    response = await manager.async_execute(
        "networkConfig",
        value={"ncid": "next", "interface": {"lan": {"name": "Core"}}},
        dry_run=False,
        confirm=True,
        expected_current_hash=str(read_response["config_hash"]),
        refresh=False,
    )

    assert response["executed"] is True
    client.async_set_item.assert_awaited_once_with(
        "networkConfig",
        value={
            "config": {
                "ncid": "next",
                "secretToken": "hidden",
                "interface": {"lan": {"enabled": True, "name": "Core"}},
            }
        },
        target="0.0.0.0",
    )


@pytest.mark.asyncio
async def test_network_config_merge_patch_can_remove_keys() -> None:
    """A null merge-patch value removes the selected network config key."""
    manager, client = _manager(
        get_result={"ncid": "current", "interface": {"lan": {}, "old": {}}}
    )

    await manager.async_execute(
        "networkConfig",
        value={"interface": {"old": None}},
    )

    assert client.async_get_item.await_args_list[1].kwargs == {
        "value": {"config": {"ncid": "current", "interface": {"lan": {}}}}
    }


@pytest.mark.asyncio
async def test_network_config_snapshot_rolls_back_without_exposing_secrets() -> None:
    """A raw snapshot can be restored by hash while its response stays redacted."""
    current = {"ncid": "current", "password": "wifi-secret"}
    manager, client = _manager(get_result=current)
    read_response = await manager.async_read("networkConfig")

    assert read_response["result"] == {
        "ncid": "current",
        "password": "[redacted]",
    }
    client.async_get_item.reset_mock()
    response = await manager.async_rollback_network_config(
        str(read_response["config_hash"])
    )

    assert response["executed"] is False
    assert response["rollback_snapshot_hash"] == read_response["config_hash"]
    client.async_set_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_config_rollback_rejects_unknown_snapshot() -> None:
    """Rollback refuses hashes not held by this loaded manager."""
    manager, client = _manager()

    with pytest.raises(ValueError, match="snapshot is unavailable"):
        await manager.async_rollback_network_config("missing")

    client.async_set_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_config_rollback_replaces_the_complete_snapshot() -> None:
    """Rollback removes keys that were added after the selected snapshot."""
    original = {"ncid": "original", "interface": {"lan": {}}}
    manager, client = _manager(get_result=original)
    original_read = await manager.async_read("networkConfig")
    current = {
        "ncid": "changed",
        "interface": {"lan": {}, "new": {"enabled": True}},
    }
    client.async_get_item.return_value = current
    current_read = await manager.async_read("networkConfig")
    client.async_get_item.reset_mock()

    response = await manager.async_rollback_network_config(
        str(original_read["config_hash"]),
        dry_run=False,
        confirm=True,
        expected_current_hash=str(current_read["config_hash"]),
    )

    assert response["executed"] is True
    assert response["network_config_mode"] == "replace"
    client.async_set_item.assert_awaited_once_with(
        "networkConfig",
        value={"config": original},
        target="0.0.0.0",
    )


@pytest.mark.asyncio
async def test_admin_execute_rejects_non_allowlisted_item() -> None:
    """Credential, shell, and unknown commands stay unreachable."""
    manager, client = _manager()

    with pytest.raises(ValueError, match="Unsupported"):
        await manager.async_execute("cmd", value={"cmd": "id"})

    client.async_command_item.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_config_read_redacts_wifi_and_vpn_keys() -> None:
    """A read hides the WireGuard, Wi-Fi and mesh keys and nothing else."""
    manager, _ = _manager(get_result=_network_config())

    response = await manager.async_read("networkConfig")

    assert response["result"] == _redacted_network_config()
    serialized = json.dumps(response)
    for secret in _SECRETS:
        assert secret not in serialized


@pytest.mark.parametrize(
    "field",
    [
        "authKey",
        "key",
        "pass",
        "passphrase",
        "password",
        "preSharedKey",
        "psk",
        "secret",
        "wpa_passphrase",
    ],
)
@pytest.mark.asyncio
async def test_admin_read_redacts_secret_fields_at_any_depth(field: str) -> None:
    """A secret is hidden by its field name, wherever the firmware puts it."""
    manager, _ = _manager(
        get_result={"history": [{"moved": [{field: "made-up", "ssid": "Example"}]}]}
    )

    response = await manager.async_read("networkConfigHistory")

    assert response["result"] == {
        "history": [{"moved": [{field: "[redacted]", "ssid": "Example"}]}]
    }


@pytest.mark.parametrize(
    "field",
    ["band", "encryption", "keyMgmt", "nat_passthrough", "publicKey", "public_key"],
)
@pytest.mark.asyncio
async def test_admin_read_keeps_non_secret_fields_readable(field: str) -> None:
    """Public keys and plain settings stay readable."""
    manager, _ = _manager(get_result={"nested": [{field: "made-up"}]})

    response = await manager.async_read("networkConfig")

    assert response["result"] == {"nested": [{field: "made-up"}]}


@pytest.mark.asyncio
async def test_network_config_hash_follows_the_raw_config() -> None:
    """A changed Wi-Fi key changes the hash, though both reads look the same."""
    manager, client = _manager(get_result=_network_config())
    first = await manager.async_read("networkConfig")
    changed = _network_config()
    changed["apc"]["profile"]["profile-1"]["key"] = "another-made-up-wifi-password"
    client.async_get_item.return_value = changed

    second = await manager.async_read("networkConfig")

    assert first["result"] == second["result"]
    assert first["config_hash"] != second["config_hash"]


@pytest.mark.asyncio
async def test_network_config_rollback_restores_the_raw_keys() -> None:
    """A rollback writes the snapshot's real keys and shows none of them."""
    manager, client = _manager(get_result=_network_config())
    original_read = await manager.async_read("networkConfig")
    changed = _network_config()
    changed["apc"]["profile"]["profile-1"]["key"] = "another-made-up-wifi-password"
    client.async_get_item.return_value = changed
    changed_read = await manager.async_read("networkConfig")

    plan = await manager.async_rollback_network_config(
        str(original_read["config_hash"])
    )
    response = await manager.async_rollback_network_config(
        str(original_read["config_hash"]),
        dry_run=False,
        confirm=True,
        expected_current_hash=str(changed_read["config_hash"]),
    )

    assert plan["value"] == _redacted_network_config()
    serialized = json.dumps([plan, response])
    for secret in (*_SECRETS, "another-made-up-wifi-password"):
        assert secret not in serialized
    client.async_set_item.assert_awaited_once_with(
        "networkConfig",
        value={"config": _network_config()},
        target="0.0.0.0",
    )


@pytest.mark.asyncio
async def test_network_config_patch_never_writes_the_redaction_placeholder() -> None:
    """A read sent back as the patch keeps every hidden key on the router."""
    manager, client = _manager(get_result=_network_config())
    read_response = await manager.async_read("networkConfig")
    patch = deepcopy(read_response["result"])
    patch["apc"]["profile"]["profile-1"]["ssid"] = "Example Renamed"

    await manager.async_execute(
        "networkConfig",
        value=patch,
        dry_run=False,
        confirm=True,
        expected_current_hash=str(read_response["config_hash"]),
        refresh=False,
    )

    expected = _network_config()
    expected["apc"]["profile"]["profile-1"]["ssid"] = "Example Renamed"
    client.async_set_item.assert_awaited_once_with(
        "networkConfig",
        value={"config": expected},
        target="0.0.0.0",
    )
    assert "[redacted]" not in json.dumps(client.async_set_item.await_args.kwargs)


@pytest.mark.parametrize(
    "patch",
    [
        # A new Wi-Fi network has no current key to keep.
        {"apc": {"profile": {"profile-2": {"ssid": "Guests", "key": "[redacted]"}}}},
        # A changed list is replaced whole, so its hidden key cannot be kept.
        {
            "interface": {
                "wireguard": {
                    "wg0": {
                        "peers": [
                            {
                                "publicKey": "made-up-peer-public-key",
                                "presharedKey": "[redacted]",
                                "allowedIPs": ["10.9.0.3/32"],
                            }
                        ]
                    }
                }
            }
        },
    ],
)
@pytest.mark.asyncio
async def test_network_config_patch_rejects_an_unresolvable_placeholder(
    patch: dict[str, object],
) -> None:
    """A placeholder that stands for no current value stops the write."""
    manager, client = _manager(get_result=_network_config())
    read_response = await manager.async_read("networkConfig")
    client.async_get_item.reset_mock()

    with pytest.raises(ValueError, match="redacted placeholder"):
        await manager.async_execute(
            "networkConfig",
            value=patch,
            dry_run=False,
            confirm=True,
            expected_current_hash=str(read_response["config_hash"]),
        )

    client.async_set_item.assert_not_awaited()
    # Only the current config was read: the impact check never saw the patch.
    client.async_get_item.assert_awaited_once_with("networkConfig")


@pytest.mark.asyncio
async def test_admin_execute_rejects_the_placeholder_in_other_writes() -> None:
    """A redacted value read from one item is never written by another."""
    manager, client = _manager()

    with pytest.raises(ValueError, match="redacted placeholder"):
        await manager.async_execute(
            "saveVpnProfile",
            value={"profileId": "home", "config": {"privateKey": "[redacted]"}},
            dry_run=False,
            confirm=True,
        )

    client.async_command_item.assert_not_awaited()
