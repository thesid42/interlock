"""Fixed-source verification for the committed Python investigator."""

import hashlib
import json
from pathlib import Path

from app.security import rca_contract


def verify_sources(files, settings):
    root = Path(__file__).resolve().parents[2]
    bundle = root / "integrations/guild/rca-investigator"
    for name in ("graph.py", "langgraph.json", "guild.yaml", "rca_contract.py"):
        local = (bundle / name).read_bytes()
        remote = files.get(name)
        if not isinstance(remote, str) or remote.encode() != local:
            raise ValueError("Published RCA source differs from the local pinned bundle: " + name)
    canonical = (root / "app/security/rca_contract.py").read_bytes()
    if canonical != (bundle / "rca_contract.py").read_bytes():
        raise ValueError("The live agent and sandbox must use identical contract bytes")
    manifest = json.loads(files["langgraph.json"])
    if manifest != {"dependencies": ["."], "graphs": {"agent": "./graph.py:graph"}}:
        raise ValueError("Unexpected Python runtime graph or dependency declaration")
    return hashlib.sha256(canonical).hexdigest()


def validate_packet(packet):
    source = Path(rca_contract.__file__).read_bytes()
    return rca_contract.validate_packet(packet, contract_sha256=hashlib.sha256(source).hexdigest())
