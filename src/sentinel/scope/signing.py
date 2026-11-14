from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from sentinel.models.scope import ScopeManifest


class SignatureError(ValueError):
    pass


def _reject_duplicate_keys(text: str) -> None:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise SignatureError("cannot parse scope manifest") from exc
    if root is None:
        raise SignatureError("scope manifest is empty")
    visited: set[int] = set()
    pending: list[yaml.Node] = [root]
    while pending:
        node = pending.pop()
        if id(node) in visited:
            continue
        visited.add(id(node))
        if isinstance(node, yaml.MappingNode):
            keys: set[str] = set()
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    raise SignatureError("scope mappings require scalar keys")
                if key_node.tag == "tag:yaml.org,2002:merge":
                    raise SignatureError("YAML merge keys are not supported in scope manifests")
                if key_node.value in keys:
                    raise SignatureError(f"duplicate scope key: {key_node.value}")
                keys.add(key_node.value)
                pending.extend((key_node, value_node))
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)


def _normalize(value: Any, key: str | None = None) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if key in {"valid_from", "valid_until"} and isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return value
    if isinstance(value, dict):
        return {item_key: _normalize(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def _payload(data: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in data.items() if key != "signature"}
    return json.dumps(_normalize(unsigned), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair(private_path: Path, public_path: Path) -> None:
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing scope signing key")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o644)


def sign_manifest(data: dict[str, Any], private_path: Path) -> dict[str, Any]:
    try:
        private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise SignatureError("cannot load Ed25519 signing key") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignatureError("signing key must be Ed25519")
    result = dict(data)
    result.pop("signature", None)
    result["signing_key_id"] = key_id(private_key.public_key())
    result["signature"] = base64.b64encode(private_key.sign(_payload(result))).decode("ascii")
    return result


def write_signed_manifest(data: dict[str, Any], scope_path: Path, private_path: Path) -> ScopeManifest:
    signed = sign_manifest(data, private_path)
    ScopeManifest.model_validate(signed)
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text(yaml.safe_dump(signed, sort_keys=False), encoding="utf-8")
    return ScopeManifest.model_validate(signed)


def load_verified_manifest(scope_path: Path, public_path: Path) -> ScopeManifest:
    try:
        manifest_text = scope_path.read_text(encoding="utf-8")
        _reject_duplicate_keys(manifest_text)
        data = yaml.safe_load(manifest_text)
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
    except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
        raise SignatureError("cannot load scope manifest or public key") from exc
    if not isinstance(data, dict) or not isinstance(public_key, Ed25519PublicKey):
        raise SignatureError("invalid manifest or non-Ed25519 public key")
    try:
        manifest = ScopeManifest.model_validate(data)
        signature = base64.b64decode(manifest.signature, validate=True)
        public_key.verify(signature, _payload(data))
    except Exception as exc:
        raise SignatureError("scope signature is invalid or manifest schema is invalid") from exc
    if manifest.signing_key_id != key_id(public_key):
        raise SignatureError("scope signing key id does not match the provided public key")
    return manifest
