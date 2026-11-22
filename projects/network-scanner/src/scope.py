"""Read and validate an unchanged lecturer-issued TCP SYN scan scope.

This module does not send packets. The manifest defines authorisation; checking
its format does not prove that a file was issued by the lecturer.
"""

import ipaddress
import json
import math
from pathlib import Path


# Supported manifest contract.
SCOPE_SCHEMA = "wqe7002-recon-scope-v1"
SUPPORTED_OPTION = "tcp-syn-scan"

# Assignment-wide ceilings; individual scopes may specify stricter limits.
MAX_PORTS = 30
MAX_RATE_PPS = 20
MAX_ATTEMPTS = 2


class ScopeError(ValueError):
    """The scope cannot be read or does not meet the scan contract."""


def _unique_object(pairs):
    """Reject duplicate JSON keys instead of silently choosing the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScopeError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _required_text(scope, field):
    value = scope.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ScopeError(f"{field} must be a non-empty string")
    if value != value.strip():
        raise ScopeError(f"{field} must not have surrounding whitespace")
    placeholders = {"todo", "tbd", "changeme", "placeholder", "replace_me"}
    if value.lower() in placeholders or "<" in value or ">" in value:
        raise ScopeError(f"{field} contains a placeholder")
    return value


def _positive_number(scope, field):
    value = scope.get(field)
    # bool is a subclass of int in Python, but is not a valid numeric setting.
    if type(value) not in (int, float):
        raise ScopeError(f"{field} must be a positive finite number")
    if value <= 0 or not math.isfinite(value):
        raise ScopeError(f"{field} must be a positive finite number")
    return value


def validate_scope(scope):
    """Check the manifest and return it without changing its values."""
    if not isinstance(scope, dict):
        raise ScopeError("Scope must be a JSON object")

    expected = {
        "schema": SCOPE_SCHEMA,
        "option": SUPPORTED_OPTION,
    }
    # These identify the supported file format and operation, not one specific
    # scope file. Different scope IDs/targets can use the same schema and option.
    for field, value in expected.items():
        if scope.get(field) != value:
            raise ScopeError(f"{field} must be {value!r}")

    # Environment is descriptive metadata, not proof of lab authorisation.
    for field in ("scope_id", "environment", "interface", "capture_point", "topology"):
        _required_text(scope, field)

    target = _required_text(scope, "target")
    # Accept one literal IPv4 host, not a DNS name or a network to expand.
    try:
        address = ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError as error:
        raise ScopeError("target must be one IPv4 address, not a hostname or CIDR") from error
    if (address.is_multicast or address.is_unspecified or address.is_loopback
            or target == "255.255.255.255"):
        raise ScopeError("target must be a unicast lab-host address")

    ports = scope.get("ports")
    # Keep an explicit allow-list. Ranges and strings are not expanded, and
    # duplicates are rejected rather than silently scheduling repeated probes.
    if not isinstance(ports, list) or not 1 <= len(ports) <= MAX_PORTS:
        raise ScopeError(f"ports must be an explicit list of 1 to {MAX_PORTS} TCP ports")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ScopeError("Each port must be an integer between 1 and 65535")
    if len(set(ports)) != len(ports):
        raise ScopeError("ports must not contain duplicates")

    if _positive_number(scope, "maximum_rate_pps") > MAX_RATE_PPS:
        raise ScopeError(f"maximum_rate_pps must not exceed {MAX_RATE_PPS}")
    attempts = scope.get("maximum_attempts")
    if type(attempts) is not int or not 1 <= attempts <= MAX_ATTEMPTS:
        raise ScopeError(f"maximum_attempts must be an integer from 1 to {MAX_ATTEMPTS}")
    _positive_number(scope, "timeout_seconds")
    return scope


def validate_response_grace(value, timeout):
    """Optional post-response window; never extend the scope's timeout."""
    if value is None:
        # No option means the original full-timeout baseline remains selected.
        return
    if (type(value) not in (int, float) or not math.isfinite(value)
            or not 0 < value <= timeout):
        raise ScopeError("response-grace must be positive, finite and no greater than the scope timeout")


def load_scope(path):
    """Load a UTF-8 JSON scope, reporting file/format errors as ScopeError."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ScopeError(f"Cannot read scope file: {error}") from error
    try:
        # object_pairs_hook sees every key, including duplicates that ordinary
        # json.loads would silently replace with the last supplied value.
        scope = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as error:
        raise ScopeError(f"Invalid scope JSON: {error}") from error
    return validate_scope(scope)
