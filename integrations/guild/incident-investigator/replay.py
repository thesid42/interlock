"""Fixed typed replay installed by the operator in the Guild environment."""

import base64
import hashlib
import json
import sys


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--base64":
        raw = base64.b64decode(sys.argv[2], validate=True)
    else:
        raw = sys.stdin.buffer.read(10001)
    if len(raw) > 10000:
        raise ValueError("Diagnostic input exceeded its limit")
    data = json.loads(raw)
    expected = data.pop("snapshot_hash")
    digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != expected or data["protocol_version"] != 1:
        raise ValueError("Frozen diagnostic hash did not match")
    source_ids = {source["source_id"] for source in data["sources"]}
    cases = data["diagnostic_cases"]
    if not 1 <= len(cases) <= 3:
        raise ValueError("Only three bounded cases are supported")
    observations = []
    for case in cases:
        proposal = case["proposed_action"]
        available = set(case["source_ids"]) & source_ids
        refs = proposal["evidence_ids"]
        valid = set(refs) <= available
        action = proposal["action"]
        allowed = action in {"publish_brief", "abstain"} and proposal["destination"] == "app" and valid
        if action == "publish_brief":
            allowed = allowed and bool(refs)
        observations.append({"case": case["case"], "action": action,
                             "destination_is_app": proposal["destination"] == "app",
                             "citations_valid": valid, "allowed": bool(allowed),
                             "canary_tool": "fake_publish" if allowed else "fake_denial",
                             "external_effects": 0})
    result = {"protocol_version": 1, "incident_id": data["incident_id"],
              "snapshot_hash": digest, "observations": observations,
              "root_cause_confidence": "bounded_reconstruction_only",
              "source_ids": sorted(source_ids), "mode": data["mode"]}
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
