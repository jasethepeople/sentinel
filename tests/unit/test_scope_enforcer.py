from __future__ import annotations

from datetime import datetime

import pytest

from sentinel.models.scope import ScopeManifest, TargetSpec
from sentinel.scope.enforcer import ScopeDenied, ScopeEnforcer


def test_domain_ip_and_cidr_scope(signed_scope: object) -> None:
    enforcer = ScopeEnforcer(signed_scope.manifest)
    assert enforcer.authorize("example.org", "recon") == "example.org"
    assert enforcer.authorize("sub.example.org", "scanning") == "sub.example.org"
    assert enforcer.authorize("192.0.2.23", "reporting") == "192.0.2.23"


def test_exclusions_override_domain_and_cidr_scope(signed_scope: object) -> None:
    enforcer = ScopeEnforcer(signed_scope.manifest)
    with pytest.raises(ScopeDenied, match="excluded"):
        enforcer.authorize("blocked.example.org", "recon")
    excluded = signed_scope.manifest.model_copy(update={"excluded_targets": ["192.0.2.0/25"]})
    with pytest.raises(ScopeDenied, match="excluded"):
        ScopeEnforcer(excluded).authorize("192.0.2.1", "recon")


def test_out_of_scope_target_and_category_are_denied(signed_scope: object) -> None:
    enforcer = ScopeEnforcer(signed_scope.manifest)
    with pytest.raises(ScopeDenied, match="outside"):
        enforcer.authorize("outside.invalid", "recon")
    with pytest.raises(ScopeDenied, match="category"):
        enforcer.authorize("example.org", "exploitation")


def test_expired_and_naive_scope_times_fail(signed_scope: object) -> None:
    enforcer = ScopeEnforcer(signed_scope.manifest)
    with pytest.raises(ScopeDenied, match="not currently valid"):
        enforcer.validate_freshness(signed_scope.manifest.valid_until)
    with pytest.raises(ScopeDenied, match="timezone-aware"):
        enforcer.validate_freshness(datetime(2026, 1, 1))


def test_url_scope_checks_scheme_port_and_path(signed_scope: object) -> None:
    raw = signed_scope.manifest.model_dump(mode="json")
    raw["authorized_targets"] = [{"type": "url", "value": "https://example.org/app"}]
    url_scope = ScopeManifest.model_validate(raw)
    enforcer = ScopeEnforcer(url_scope)
    assert enforcer.authorize("https://example.org/app/page", "scanning") == "example.org"
    for target in ("http://example.org/app", "https://example.org:8443/app", "https://example.org/outside"):
        with pytest.raises(ScopeDenied):
            enforcer.authorize(target, "scanning")


def test_invalid_signed_scope_declarations_fail_closed(signed_scope: object) -> None:
    manifest = signed_scope.manifest.model_copy(
        update={"authorized_targets": [TargetSpec.model_construct(type="domain", value="bad")]}
    )
    with pytest.raises(ScopeDenied, match="invalid authorized"):
        ScopeEnforcer(manifest)
    manifest = signed_scope.manifest.model_copy(update={"excluded_targets": ["invalid target"]})
    with pytest.raises(ScopeDenied, match="invalid excluded"):
        ScopeEnforcer(manifest)
