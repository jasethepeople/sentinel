from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel.scope.signing import SignatureError, generate_keypair, load_verified_manifest, write_signed_manifest


def test_generated_scope_is_signed_and_private_key_is_private(signed_scope: object) -> None:
    manifest = load_verified_manifest(signed_scope.scope_file, signed_scope.public_key_file)
    assert manifest.engagement_id == "test-engagement"
    assert manifest.mode == "mock_only"
    assert signed_scope.private_key_file.stat().st_mode & 0o777 == 0o600


def test_tampered_scope_fails_signature_verification(signed_scope: object) -> None:
    data = yaml.safe_load(signed_scope.scope_file.read_text(encoding="utf-8"))
    data["authorized_targets"][0]["value"] = "attacker.example"
    signed_scope.scope_file.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(SignatureError):
        load_verified_manifest(signed_scope.scope_file, signed_scope.public_key_file)


def test_duplicate_yaml_keys_are_rejected(signed_scope: object) -> None:
    signed_scope.scope_file.write_text("engagement_id: first\nengagement_id: second\n", encoding="utf-8")
    with pytest.raises(SignatureError):
        load_verified_manifest(signed_scope.scope_file, signed_scope.public_key_file)


def test_wrong_public_key_is_rejected(signed_scope: object, tmp_path: Path) -> None:
    other_private = tmp_path / "other.pem"
    other_public = tmp_path / "other.pub"
    generate_keypair(other_private, other_public)
    with pytest.raises(SignatureError):
        load_verified_manifest(signed_scope.scope_file, other_public)


def test_manifest_cannot_be_signed_with_non_ed25519_key(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("{}", encoding="utf-8")
    bad_key = tmp_path / "bad.pem"
    bad_key.write_text("not a key", encoding="utf-8")
    with pytest.raises(SignatureError):
        write_signed_manifest({}, scope_file, bad_key)
