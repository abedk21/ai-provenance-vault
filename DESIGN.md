# Provenance Vault: cryptographic framing

This is a **demonstration of integrity controls**, not a secure artifact-supply-chain implementation.

1. Hash the bytes of each regular file using SHA-256, with a deterministic sorted relative path list.
2. Build each leaf from a domain-separated hash: `SHA256("leaf\\0" || relative_path || "\\0" || raw_file_sha256)`.
3. Build parent nodes from `SHA256("node\\0" || left || right)` and duplicate a lone trailing node.
4. Canonically serialize the JSON manifest using sorted keys and compact separators.
5. Produce `HMAC_SHA256(secret, "provenance-vault-v1\\0" || manifest_bytes)` and store only the resulting MAC and manifest digest.
6. Verify the attestation, Merkle root, and actual filesystem state. Apply configured file-count, byte-size, and extension rules.
7. For lineage, set `parent_root` to the previous run's Merkle root, and report added/removed/changed paths.

An HMAC cannot be verified without the shared secret; this is intentionally different from public-key signatures. A trusted builder and independent immutable provenance are necessary for real release security.

## Threat model

Detects local accidental changes or tampering when the expected signed manifest and its HMAC key are maintained independently. Does **not** defend against a hostile key holder, privileged filesystem manipulator, TOCTOU races, or rollback of both manifest and attestation. Path traversal and symlink rejection are explicit educational controls, not a hardened OS sandbox.
