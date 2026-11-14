from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sentinel.models.scope import ScopeManifest, TargetSpec

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeDenied(PermissionError):
    pass


def _domain(host: str) -> str:
    try:
        normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeDenied("invalid target hostname") from exc
    labels = normalized.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ScopeDenied("invalid target hostname")
    return normalized


def _target_parts(value: str) -> tuple[str, str | None, int | None, str]:
    if not value or value != value.strip() or any(char.isspace() for char in value):
        raise ScopeDenied("invalid target format")
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
                or parsed.query
            ):
                raise ScopeDenied("target URL must be an http(s) origin without credentials or fragment")
            port = parsed.port
            host = parsed.hostname
        except ValueError as exc:
            raise ScopeDenied("invalid target URL") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ScopeDenied("invalid target port")
        try:
            normalized_host = str(ipaddress.ip_address(host))
        except ValueError:
            normalized_host = _domain(host)
        return (
            normalized_host,
            parsed.scheme.lower(),
            port or (443 if parsed.scheme.lower() == "https" else 80),
            parsed.path or "/",
        )
    try:
        return str(ipaddress.ip_address(value)), None, None, "/"
    except ValueError:
        return _domain(value), None, None, "/"


def _matches_spec(host: str, scheme: str | None, port: int | None, path: str, spec: TargetSpec) -> bool:
    try:
        if spec.type == "ip":
            return host == str(ipaddress.ip_address(spec.value))
        if spec.type == "cidr":
            address = ipaddress.ip_address(host)
            return address in ipaddress.ip_network(spec.value, strict=False)
        if spec.type == "domain":
            allowed = _domain(spec.value)
            return host == allowed or host.endswith("." + allowed)
        allowed_host, allowed_scheme, allowed_port, allowed_path = _target_parts(spec.value)
        if allowed_scheme is None:
            return False
        allowed_parts = urlsplit(spec.value)
        normalized_path = allowed_path.rstrip("/") or "/"
        path_matches = path == normalized_path or path.startswith(normalized_path.rstrip("/") + "/")
        return (
            host == allowed_host
            and scheme == allowed_scheme
            and port == allowed_port
            and path_matches
            and not allowed_parts.query
        )
    except (ValueError, ScopeDenied):
        return False


def _is_excluded(host: str, scheme: str | None, port: int | None, path: str, raw: str) -> bool:
    if raw.startswith("*."):
        excluded = _domain(raw[2:])
        return host == excluded or host.endswith("." + excluded)
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    if "://" in raw:
        try:
            excluded_host, excluded_scheme, excluded_port, excluded_path = _target_parts(raw)
            path_prefix = excluded_path.rstrip("/") or "/"
            return (
                host == excluded_host
                and scheme == excluded_scheme
                and port == excluded_port
                and (path == path_prefix or path.startswith(path_prefix.rstrip("/") + "/"))
            )
        except ScopeDenied as exc:
            raise ScopeDenied("invalid excluded target in signed scope") from exc
    try:
        excluded = _domain(raw)
        return host == excluded or host.endswith("." + excluded)
    except ScopeDenied:
        try:
            return host == str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ScopeDenied("invalid excluded target in signed scope") from exc


def _validate_scope_declarations(manifest: ScopeManifest) -> None:
    for spec in manifest.authorized_targets:
        try:
            if spec.type == "ip":
                ipaddress.ip_address(spec.value)
            elif spec.type == "cidr":
                ipaddress.ip_network(spec.value, strict=False)
            elif spec.type == "domain":
                _domain(spec.value)
            else:
                _, scheme, _, _ = _target_parts(spec.value)
                if scheme is None:
                    raise ScopeDenied("URL scope entries must use http or https")
        except (ValueError, ScopeDenied) as exc:
            raise ScopeDenied("signed scope contains an invalid authorized target") from exc
    for raw in manifest.excluded_targets:
        try:
            if raw.startswith("*."):
                _domain(raw[2:])
            elif "://" in raw:
                _, scheme, _, _ = _target_parts(raw)
                if scheme is None:
                    raise ScopeDenied("excluded URL entries must use http or https")
            else:
                try:
                    ipaddress.ip_network(raw, strict=False)
                except ValueError:
                    try:
                        _domain(raw)
                    except ScopeDenied:
                        ipaddress.ip_address(raw)
        except (ValueError, ScopeDenied) as exc:
            raise ScopeDenied("signed scope contains an invalid excluded target") from exc


class ScopeEnforcer:
    def __init__(self, manifest: ScopeManifest) -> None:
        self.manifest = manifest
        if manifest.mode != "mock_only":
            raise ScopeDenied("only mock-only scopes are accepted")
        _validate_scope_declarations(manifest)

    def validate_freshness(self, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ScopeDenied("current time must be timezone-aware")
        if current < self.manifest.valid_from or current >= self.manifest.valid_until:
            raise ScopeDenied("signed scope is not currently valid")

    def authorize(self, target: str, category: str) -> str:
        self.validate_freshness()
        if self.manifest.mode != "mock_only":
            raise ScopeDenied("only mock-only scopes are accepted")
        if category not in self.manifest.allowed_tool_categories:
            raise ScopeDenied("tool category is not authorized by the signed scope")
        host, scheme, port, path = _target_parts(target)
        if any(_is_excluded(host, scheme, port, path, item) for item in self.manifest.excluded_targets):
            raise ScopeDenied("target is explicitly excluded")
        if not any(_matches_spec(host, scheme, port, path, spec) for spec in self.manifest.authorized_targets):
            raise ScopeDenied("target is outside the signed scope")
        return host
