# version.py - Single Source of Truth for Platform & Agent Versions
"""
Defines the official platform, agent, and minimum supported versions,
along with the embedded Ed25519 public key used to cryptographically
verify autonomous agent self-updates.
"""
import re

PLATFORM_VERSION = "2.1.4"
AGENT_VERSION = "2.1.4"
MIN_SUPPORTED_AGENT_VERSION = "1.6.0"

# Ed25519 Public Key embedded in all agents to verify update manifests
# Private key lives only in release tooling/CI (NEVER on production dashboard or repo)
AGENT_ED25519_PUBLIC_KEY_HEX = "e35f2ca46d8d1d6d0af3152e5a324dd56196dbdd69ca30af06461f24cbd9c970"

def parse_semver(v):
    """Extract integer components from a version string (e.g. '2.1.0' -> [2, 1, 0])."""
    try:
        parts = [int(x) for x in re.findall(r'\d+', str(v))]
        return parts if parts else [0]
    except Exception:
        return [0]

def is_newer_version(candidate_v, current_v):
    """Returns True if candidate_v is strictly newer than current_v."""
    return parse_semver(candidate_v) > parse_semver(current_v)

def is_supported_version(v):
    """Returns True if v meets or exceeds MIN_SUPPORTED_AGENT_VERSION."""
    return parse_semver(v) >= parse_semver(MIN_SUPPORTED_AGENT_VERSION)
