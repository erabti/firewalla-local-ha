"""Guarded local-administration orchestration for Firewalla Local."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from typing import TYPE_CHECKING, Final, cast

from ..api import FirewallaApiClient
from ..const import DEFAULT_INIT_TARGET
from .base_manager import FirewallaBaseManager

if TYPE_CHECKING:
    from ..coordinator import FirewallaConfigEntry, FirewallaDataUpdateCoordinator

ADMIN_READ_ITEMS: Final = (
    "auditLogs",
    "assetsConfig",
    "availableWlans",
    "customizedCategories",
    "dataPlan",
    "dhcpLease",
    "eptGroup",
    "excludedDomains",
    "exceptions",
    "includedDomains",
    "networkConfig",
    "networkConfigHistory",
    "networkProfiles",
    "networkState",
    "networkStatus",
    "ovpnProfiles",
    "policies",
    "publicIp",
    "sysInfo",
    "timezone",
    "upstreamDns",
    "userConfig",
    "vpnProfiles",
    "wanConnectivity",
    "wanInterfaces",
    "wlanChannels",
)

ADMIN_SET_ITEMS: Final = (
    "autoSpoof",
    "autoUpgrade",
    "cpuProfile",
    "dataPlan",
    "dhcp",
    "dhcpSpoof",
    "eptGroupName",
    "forceNotificationLocalization",
    "includeNameInNotification",
    "manualSpoof",
    "mode",
    "networkConfig",
    "policy",
    "router",
    "spoof",
    "tag",
    "timezone",
    "userConfig",
)

ADMIN_COMMAND_ITEMS: Final = (
    "addExcludeDomain",
    "addIncludeDomain",
    "createOrUpdateCustomizedCategory",
    "createOrUpdateRuleGroup",
    "createOrUpdateVirtWanGroup",
    "customIntel:update",
    "ddnsUpdate",
    "deleteCategory",
    "deleteOvpnProfile",
    "deleteVpnProfile",
    "disableBinding",
    "disableFeature",
    "dnsmasq",
    "enableFeature",
    "enableBinding",
    "exception:create",
    "exception:delete",
    "exception:update",
    "host:pin",
    "host:unpin",
    "manualSpoofUpdate",
    "networkInterface:reset",
    "networkInterface:revert",
    "networkInterface:update",
    "policy:create",
    "policy:batch",
    "policy:delete",
    "policy:disable",
    "policy:enable",
    "policy:resetStats",
    "policy:setDisableAll",
    "policy:toggle",
    "policy:update",
    "removeCustomizedCategory",
    "removeExcludeDomain",
    "removeIncludeDomain",
    "removeRuleGroup",
    "removeUPnP",
    "removeVirtWanGroup",
    "renewDHCPLease",
    "saveOvpnProfile",
    "saveVpnProfile",
    "setManualSpoof",
    "staBssSteer",
    "startVpnClient",
    "stopVpnClient",
    "tag:create",
    "tag:remove",
    "updateIncludedElements",
    "user",
    "vipProfile:create",
    "vipProfile:delete",
    "vpnProfile:delete",
    "vpnProfile:grant",
    "wifi:switch",
)

ADMIN_EXCLUDED_ITEMS: Final[dict[str, str]] = {
    "apt-get": "operating-system package control",
    "cmd": "arbitrary shell execution",
    "debugOn": "runtime debug control",
    "debugOff": "runtime debug control",
    "generateRSAPublicKey": "credential management",
    "migration:export": "migration and secret archive control",
    "migration:import": "migration and secret archive control",
    "reboot": "appliance power control",
    "resetSSHPassword": "credential management",
    "saveRSAPublicKey": "credential management",
    "shutdown": "appliance power control",
    "sshPrivateKey": "credential access",
    "switchBranch": "firmware lifecycle control",
    "upgrade": "firmware lifecycle control",
}

_SENSITIVE_KEY_FRAGMENTS: Final = (
    "certificate",
    "credential",
    "passphrase",
    "passwd",
    "password",
    "private",
    "psk",
    "secret",
    "token",
)
# "pass" is matched whole: as a fragment it would hide ``nat_passthrough``.
_SENSITIVE_KEY_NAMES: Final = frozenset({"pass"})
_KEY_SUFFIXES: Final = ("key", "keys")
_PUBLIC_KEY_SUFFIXES: Final = ("publickey", "publickeys", "pubkey", "pubkeys")
_REDACTED_VALUE: Final = "[redacted]"
_NETWORK_CONFIG_ITEM: Final = "networkConfig"
_NETWORK_CONFIG_IMPACT_ITEM: Final = "networkConfigImpact"
_NETWORK_SNAPSHOT_LIMIT: Final = 5


def _canonical_hash(value: object) -> str:
    """Return a stable SHA-256 hash for one JSON-compatible value."""
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _is_sensitive_key(key: str) -> bool:
    """Return whether a field name looks like it holds a secret.

    The rule goes by name at any depth, not by path, so a firmware change in
    the layout stays covered. Any field ending in ``key`` is a secret (a Wi-Fi
    profile's and the mesh's are plain ``key``) unless it is a public key.
    """
    name = key.casefold().replace("_", "").replace("-", "")
    if name in _SENSITIVE_KEY_NAMES:
        return True
    if any(fragment in name for fragment in _SENSITIVE_KEY_FRAGMENTS):
        return True
    return name.endswith(_KEY_SUFFIXES) and not name.endswith(_PUBLIC_KEY_SUFFIXES)


def _redact_sensitive(value: object) -> object:
    """Recursively redact secret-like response fields."""
    if isinstance(value, Mapping):
        redacted: dict[str, object] = {}
        for raw_key, nested_value in value.items():
            key = str(raw_key)
            redacted[key] = (
                _REDACTED_VALUE
                if _is_sensitive_key(key)
                else _redact_sensitive(nested_value)
            )
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive(item) for item in value]
    return value


def _find_redacted_placeholder(value: object, path: str = "") -> str | None:
    """Return the path of the first redaction placeholder in a value, if any."""
    if value == _REDACTED_VALUE:
        return path or "value"
    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            nested_path = f"{path}.{key}" if path else str(key)
            if (
                found := _find_redacted_placeholder(nested_value, nested_path)
            ) is not None:
                return found
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            if (
                found := _find_redacted_placeholder(item, f"{path}[{index}]")
            ) is not None:
                return found
    return None


def _apply_network_config_patch(
    current: Mapping[str, object],
    patch: Mapping[str, object],
    path: str = "",
) -> dict[str, object]:
    """Apply an RFC 7396-style merge patch while preserving hidden values.

    A redaction placeholder means "keep the current value", so a caller can
    send back what it read. The placeholder itself is never written: it is
    refused where there is no current value to keep, and inside a changed
    list, because a merge patch replaces a list whole.
    """
    merged = deepcopy(dict(current))
    for key, patch_value in patch.items():
        key_path = f"{path}.{key}" if path else str(key)
        if patch_value is None:
            merged.pop(key, None)
            continue
        if patch_value == _REDACTED_VALUE:
            if key not in merged:
                raise ValueError(
                    f"networkConfig patch has the redacted placeholder at "
                    f"{key_path}, where there is no current value to keep; "
                    "send the real value or leave the key out"
                )
            continue
        current_value = merged.get(key)
        if isinstance(patch_value, Mapping):
            nested_current = current_value if isinstance(current_value, Mapping) else {}
            merged[key] = _apply_network_config_patch(
                nested_current, patch_value, key_path
            )
            continue
        if (found := _find_redacted_placeholder(patch_value, key_path)) is not None:
            if _redact_sensitive(current_value) == patch_value:
                # The list came back as it was read: keep its hidden values.
                continue
            raise ValueError(
                f"networkConfig patch has the redacted placeholder at {found}, "
                "inside a changed list; a list is replaced whole, so send its "
                "real values or leave the list out"
            )
        merged[key] = deepcopy(patch_value)
    return merged


class FirewallaAdminManager(FirewallaBaseManager):
    """Own the allowlisted expert administration surface."""

    def __init__(
        self,
        coordinator: FirewallaDataUpdateCoordinator,
        entry: FirewallaConfigEntry,
        client: FirewallaApiClient,
    ) -> None:
        """Initialize the manager and its bounded rollback snapshot cache."""
        super().__init__(coordinator, entry, client)
        self._network_config_snapshots: dict[str, dict[str, object]] = {}

    def _store_network_config_snapshot(self, config: dict[str, object]) -> str:
        """Keep a bounded raw snapshot for rollback without exposing secrets."""
        snapshot_hash = _canonical_hash(config)
        self._network_config_snapshots.pop(snapshot_hash, None)
        self._network_config_snapshots[snapshot_hash] = deepcopy(config)
        while len(self._network_config_snapshots) > _NETWORK_SNAPSHOT_LIMIT:
            oldest_hash = next(iter(self._network_config_snapshots))
            self._network_config_snapshots.pop(oldest_hash)
        return snapshot_hash

    def get_capabilities(self) -> dict[str, object]:
        """Return the supported protocol items and mutation safeguards."""
        return {
            "read_items": list(ADMIN_READ_ITEMS),
            "set_items": list(ADMIN_SET_ITEMS),
            "command_items": list(ADMIN_COMMAND_ITEMS),
            "excluded_items": dict(ADMIN_EXCLUDED_ITEMS),
            "safeguards": {
                "writes_default_to_dry_run": True,
                "write_confirmation_required": True,
                "network_config_expected_hash_required": True,
                "network_config_impact_check_required": True,
                "sensitive_response_fields_redacted": True,
                "raw_network_snapshots_kept_in_memory": _NETWORK_SNAPSHOT_LIMIT,
            },
        }

    async def async_read(
        self,
        item: str,
        *,
        value: dict[str, object] | None = None,
        target: str = DEFAULT_INIT_TARGET,
    ) -> dict[str, object]:
        """Read one allowlisted local runtime item."""
        if item not in ADMIN_READ_ITEMS:
            raise ValueError(f"Unsupported Firewalla admin read item: {item}")

        result = await self.client.async_get_item(item, value=value, target=target)
        response: dict[str, object] = {
            "item": item,
            "target": target,
            "result": _redact_sensitive(result),
        }
        if item == _NETWORK_CONFIG_ITEM and isinstance(result, dict):
            response["config_hash"] = self._store_network_config_snapshot(result)
        return response

    async def async_execute(
        self,
        item: str,
        *,
        value: dict[str, object],
        target: str = DEFAULT_INIT_TARGET,
        dry_run: bool = True,
        confirm: bool = False,
        expected_current_hash: str | None = None,
        refresh: bool = True,
        _replace_network_config: bool = False,
    ) -> dict[str, object]:
        """Plan or execute one allowlisted local runtime mutation."""
        if item not in ADMIN_SET_ITEMS and item not in ADMIN_COMMAND_ITEMS:
            raise ValueError(f"Unsupported Firewalla admin write item: {item}")

        if (
            item != _NETWORK_CONFIG_ITEM
            and (found := _find_redacted_placeholder(value)) is not None
        ):
            raise ValueError(
                f"value has the redacted placeholder at {found}; it would be "
                "written as that literal text, so send the real value"
            )

        message_type = "set" if item in ADMIN_SET_ITEMS else "cmd"
        response: dict[str, object] = {
            "item": item,
            "message_type": message_type,
            "target": target,
            "dry_run": dry_run,
            "confirmed": confirm,
        }

        requested_network_config: dict[str, object] | None = None
        if item == _NETWORK_CONFIG_ITEM:
            current_config = await self.client.async_get_item(_NETWORK_CONFIG_ITEM)
            if not isinstance(current_config, dict):
                raise ValueError(
                    "Firewalla networkConfig read did not return an object"
                )
            current_hash = _canonical_hash(current_config)
            self._store_network_config_snapshot(current_config)
            requested_network_config = (
                deepcopy(value)
                if _replace_network_config
                else _apply_network_config_patch(current_config, value)
            )
            response["current_config_hash"] = current_hash
            response["network_config_mode"] = (
                "replace" if _replace_network_config else "merge_patch"
            )
            response["requested_config_hash"] = _canonical_hash(
                requested_network_config
            )
            response["impact"] = _redact_sensitive(
                await self.client.async_get_item(
                    _NETWORK_CONFIG_IMPACT_ITEM,
                    value={"config": requested_network_config},
                )
            )

            if not dry_run:
                if not expected_current_hash:
                    raise ValueError(
                        "expected_current_hash is required for networkConfig writes"
                    )
                if expected_current_hash != current_hash:
                    raise ValueError(
                        "networkConfig changed after it was read; "
                        "read it again before writing"
                    )

        if dry_run:
            response["executed"] = False
            response["value"] = _redact_sensitive(value)
            return response

        if not confirm:
            raise ValueError("confirm must be true when dry_run is false")

        wire_value = cast(
            dict[str, object],
            (
                {"config": requested_network_config}
                if item == _NETWORK_CONFIG_ITEM
                else value
            ),
        )
        if message_type == "set":
            result = await self.client.async_set_item(
                item,
                value=wire_value,
                target=target,
            )
        else:
            result = await self.client.async_command_item(
                item,
                value=wire_value,
                target=target,
            )

        response["executed"] = True
        response["result"] = _redact_sensitive(result)
        if refresh:
            await self.coordinator.async_request_refresh()
            response["refreshed"] = True
        else:
            response["refreshed"] = False
        return response

    async def async_rollback_network_config(
        self,
        snapshot_hash: str,
        *,
        expected_current_hash: str | None = None,
        dry_run: bool = True,
        confirm: bool = False,
        refresh: bool = False,
    ) -> dict[str, object]:
        """Plan or restore one raw network snapshot held by this manager."""
        snapshot = self._network_config_snapshots.get(snapshot_hash)
        if snapshot is None:
            raise ValueError(
                "network snapshot is unavailable; read networkConfig again or "
                "use Firewalla's native config history"
            )
        response = await self.async_execute(
            _NETWORK_CONFIG_ITEM,
            value=deepcopy(snapshot),
            dry_run=dry_run,
            confirm=confirm,
            expected_current_hash=expected_current_hash,
            refresh=refresh,
            _replace_network_config=True,
        )
        response["rollback_snapshot_hash"] = snapshot_hash
        return response
