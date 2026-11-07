"""Bounded reproducibility manifests with HMAC demo attestations.

This is not SLSA, Sigstore, PKI, or a trusted build system. A shared secret
and a local filesystem are NOT a public or independently verifiable identity.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

MAX_FILES = 500
MAX_FILE_SIZE = 10_000_000
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")


class VaultError(ValueError):
    pass


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def valid_relpath(value: str) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    p = PurePosixPath(value)
    return (not p.is_absolute() and value == p.as_posix() and
            all(part not in (".", "..") for part in value.split("/")))


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def merkle_root(files: list[dict]) -> str:
    """Stable domain-separated Merkle root over sorted (path, sha256) leaves."""
    if not files:
        raise VaultError("Empty artifact sets are unsupported")
    paths = [f.get("path") for f in files]
    if not all(valid_relpath(p) for p in paths) or paths != sorted(paths) or len(set(paths)) != len(paths):
        raise VaultError("File list must have sorted, distinct relative paths")
    if any(not isinstance(f.get("sha256"),str) or not HEX64.fullmatch(f["sha256"]) for f in files):
        raise VaultError("File digest must be SHA-256 hex")
    level = [hashlib.sha256(b"leaf\x00" + f["path"].encode("utf-8") + b"\x00" + bytes.fromhex(f["sha256"])).digest() for f in files]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b"node\x00" + level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def walk_files(root: Path) -> list[Path]:
    root = root.resolve()
    if not root.is_dir():
        raise VaultError("Root must be an existing directory")
    files: list[Path] = []
    for cur, dirs, names in os.walk(root, followlinks=False):
        for dirname in dirs:
            if (Path(cur) / dirname).is_symlink():
                raise VaultError("Symlink directories are not permitted")
        for name in names:
            p = Path(cur) / name
            if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
                raise VaultError("Only ordinary, contained files are permitted")
            if p.stat().st_size > MAX_FILE_SIZE:
                raise VaultError("File exceeds 10 MB demo limit")
            files.append(p)
            if len(files) > MAX_FILES:
                raise VaultError("Too many files")
    return sorted(files)


def build_manifest(root: Path, project: str, run_id: str, created_at: str,
                   parent_root: str | None = None) -> dict:
    if not isinstance(project,str) or not LABEL.fullmatch(project):
        raise VaultError("Project label invalid")
    if not isinstance(run_id,str) or not LABEL.fullmatch(run_id):
        raise VaultError("Run label invalid")
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except (TypeError, AttributeError, ValueError) as exc:
        raise VaultError("Invalid created_at timestamp") from exc
    if dt.tzinfo is None:
        raise VaultError("created_at requires a timezone")
    if parent_root is not None and (not isinstance(parent_root,str) or not HEX64.fullmatch(parent_root)):
        raise VaultError("parent_root must be a previous Merkle SHA-256 root")
    root = Path(root).resolve()
    files = [{"path": p.relative_to(root).as_posix(), "size": p.stat().st_size,
              "sha256": sha_file(p)} for p in walk_files(root)]
    files.sort(key=lambda f: f["path"])
    return {"schema": "provenance-vault/v1", "project": project, "run_id": run_id,
            "created_at": created_at, "parent_root": parent_root,
            "files": files, "merkle_root": merkle_root(files)}


def sign_manifest(manifest: dict, secret: bytes) -> dict:
    if not isinstance(secret,bytes) or len(secret) < 16:
        raise VaultError("HMAC demo key must be at least 16 bytes")
    data = canonical(manifest)
    digest = hashlib.sha256(data).hexdigest()
    signature = hmac.new(secret, b"provenance-vault-v1\x00" + data, hashlib.sha256).hexdigest()
    return {"scheme": "HMAC-SHA256-demo", "manifest_sha256": digest, "signature": signature}


def policy_issues(manifest: dict, policy: dict | None) -> list[str]:
    if policy is None:
        return []
    if not isinstance(policy,dict):
        raise VaultError("Policy must be a JSON object")
    problems = []
    files = manifest.get("files",[])
    max_files = policy.get("max_files")
    max_bytes = policy.get("max_total_bytes")
    allowed = policy.get("extensions")
    if max_files is not None:
        if type(max_files) is not int or max_files < 0:
            raise VaultError("max_files must be nonnegative")
        if len(files) > max_files: problems.append("policy_file_count")
    if max_bytes is not None:
        if type(max_bytes) is not int or max_bytes < 0:
            raise VaultError("max_total_bytes must be nonnegative")
        if sum(f.get("size",0) for f in files) > max_bytes: problems.append("policy_total_bytes")
    if allowed is not None:
        if not isinstance(allowed,list) or any(not isinstance(s,str) or not s.startswith(".") for s in allowed):
            raise VaultError("extensions must be a list of dotted suffixes")
        if any(Path(f['path']).suffix not in allowed for f in files): problems.append("policy_extension")
    return problems


def verify_manifest(root: Path, manifest: dict, attestation: dict, secret: bytes,
                    *, strict_extra: bool = True, policy: dict | None = None) -> dict:
    issues: list[str] = []
    if not isinstance(manifest,dict) or not isinstance(attestation,dict):
        raise VaultError("Manifest and attestation must be objects")
    if manifest.get("schema") != "provenance-vault/v1": issues.append("invalid_schema")
    files = manifest.get("files")
    if not isinstance(files,list) or len(files) > MAX_FILES: raise VaultError("Invalid manifest file list")
    for f in files:
        if not isinstance(f,dict) or not valid_relpath(f.get("path")) or type(f.get("size")) is not int or f["size"] < 0 or not isinstance(f.get("sha256"),str) or not HEX64.fullmatch(f["sha256"]):
            raise VaultError("Unsafe or invalid manifest file entry")
    computed_root = merkle_root(files)
    if manifest.get("merkle_root") != computed_root: issues.append("merkle_root_mismatch")
    if attestation.get("scheme") != "HMAC-SHA256-demo": issues.append("unknown_attestation_scheme")
    if attestation.get("manifest_sha256") != hashlib.sha256(canonical(manifest)).hexdigest():
        issues.append("manifest_digest_mismatch")
    expected = sign_manifest(manifest,secret)["signature"]
    supplied = attestation.get("signature")
    if not isinstance(supplied,str) or not hmac.compare_digest(expected,supplied):
        issues.append("signature_mismatch")
    root = Path(root).resolve()
    if not root.is_dir(): raise VaultError("Missing artifact directory")
    expected_names = {f["path"] for f in files}
    try:
        actual_names = {p.relative_to(root).as_posix() for p in walk_files(root)}
    except VaultError:
        issues.append("unsafe_file_or_symlink")
        actual_names = set()
    if strict_extra and actual_names - expected_names: issues.append("unexpected_files")
    if expected_names - actual_names: issues.append("missing_files")
    for f in files:
        p = root / f["path"]
        if f["path"] in actual_names:
            if p.stat().st_size != f["size"]: issues.append(f"size_mismatch:{f['path']}")
            if sha_file(p) != f["sha256"]: issues.append(f"sha_mismatch:{f['path']}")
    issues.extend(policy_issues(manifest,policy))
    return {"ok": not issues, "issues": sorted(set(issues)),
            "file_count": len(files), "trusted_head": manifest.get("merkle_root")}


def compare_manifests(old: dict, new: dict) -> dict:
    if new.get("parent_root") != old.get("merkle_root"):
        raise VaultError("New run does not reference the old run's root")
    a = {f["path"]:f["sha256"] for f in old.get("files",[])}
    b = {f["path"]:f["sha256"] for f in new.get("files",[])}
    return {"added": sorted(b.keys()-a.keys()), "removed": sorted(a.keys()-b.keys()),
            "modified": sorted(k for k in a.keys()&b.keys() if a[k]!=b[k]),
            "from_root": old["merkle_root"], "to_root": new["merkle_root"]}
