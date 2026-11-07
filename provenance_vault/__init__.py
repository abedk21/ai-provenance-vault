"""Educational reproducibility manifests with HMAC attestations."""
from .core import build_manifest, sign_manifest, verify_manifest, compare_manifests
__all__ = ["build_manifest", "sign_manifest", "verify_manifest", "compare_manifests"]
