#!/usr/bin/env python3
"""
release_signer.py — Cryptographic Signing Tool for Autonomous Agent Updates.
Used in CI / Release Tooling to sign Python agent artifacts with Ed25519.
Produces SHA-256 digests and base64 signatures for update manifests.
"""

import os
import sys
import hashlib
import json
import base64
from typing import Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

import version
import agent_verifier

DEFAULT_RELEASE_PRIV_KEY_HEX = os.environ.get("AGENT_RELEASE_PRIVATE_KEY_HEX")

def sign_agent_artifact(agent_bytes: bytes, private_key_hex: Optional[str] = None) -> Dict[str, Any]:
    """
    Signs raw agent bytes with Ed25519 and calculates SHA-256 and byte length.
    Returns manifest dictionary.
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required for release artifact signing.")
    
    priv_hex = private_key_hex or DEFAULT_RELEASE_PRIV_KEY_HEX
    if not priv_hex:
        raise RuntimeError("AGENT_RELEASE_PRIVATE_KEY_HEX environment variable required. Private key must not be hardcoded in repository.")
    priv_bytes = bytes.fromhex(priv_hex)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # 1. SHA-256 Digest
    sha256_hash = hashlib.sha256(agent_bytes).hexdigest()

    # 2. Ed25519 Digital Signature over raw artifact bytes
    raw_sig = priv.sign(agent_bytes)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")

    return {
        "version": version.AGENT_VERSION,
        "target_version": version.AGENT_VERSION,
        "min_supported_version": version.MIN_SUPPORTED_AGENT_VERSION,
        "sha256": sha256_hash,
        "signature": sig_b64,
        "size": len(agent_bytes),
        "public_key": version.AGENT_ED25519_PUBLIC_KEY_HEX
    }

def sign_file(input_file_path: str, output_manifest_path: Optional[str] = None, private_key_hex: Optional[str] = None) -> Dict[str, Any]:
    with open(input_file_path, "rb") as f:
        data = f.read()
    manifest = sign_agent_artifact(data, private_key_hex)
    if output_manifest_path:
        with open(output_manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
    return manifest

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: release_signer.py <agent_file.py> [manifest_out.json]")
        sys.exit(1)
    in_file = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else f"{in_file}.manifest.json"
    m = sign_file(in_file, out_file)
    print(f"Successfully signed {in_file} -> {out_file}")
    print(json.dumps(m, indent=2))
