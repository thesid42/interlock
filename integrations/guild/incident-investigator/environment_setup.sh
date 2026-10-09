#!/usr/bin/env bash
set -euo pipefail
if ! command -v python3 >/dev/null; then
  printf '%s\n' 'Interlock setup failed: the selected image needs python3.' >&2
  exit 1
fi
# Install reviewed worker bytes at a shared absolute path, independent of HOME.
python3 -I -B <<'INTERLOCK_SETUP_PY'
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile

expected_sha256 = 'd9032c6b242afd05454b670da010fe068e737a9e4cfdc4b2cd69b007dbcf8937'
encoded_worker = 'IiIiRml4ZWQgdHlwZWQgcmVwbGF5IGluc3RhbGxlZCBieSB0aGUgb3BlcmF0b3IgaW4gdGhlIEd1aWxkIGVudmlyb25tZW50LiIiIgoKaW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQganNvbgppbXBvcnQgc3lzCgoKZGVmIG1haW4oKToKICAgIGlmIGxlbihzeXMuYXJndikgPT0gMyBhbmQgc3lzLmFyZ3ZbMV0gPT0gIi0tYmFzZTY0IjoKICAgICAgICByYXcgPSBiYXNlNjQuYjY0ZGVjb2RlKHN5cy5hcmd2WzJdLCB2YWxpZGF0ZT1UcnVlKQogICAgZWxzZToKICAgICAgICByYXcgPSBzeXMuc3RkaW4uYnVmZmVyLnJlYWQoMTAwMDEpCiAgICBpZiBsZW4ocmF3KSA+IDEwMDAwOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoIkRpYWdub3N0aWMgaW5wdXQgZXhjZWVkZWQgaXRzIGxpbWl0IikKICAgIGRhdGEgPSBqc29uLmxvYWRzKHJhdykKICAgIGV4cGVjdGVkID0gZGF0YS5wb3AoInNuYXBzaG90X2hhc2giKQogICAgZGlnZXN0ID0gaGFzaGxpYi5zaGEyNTYoanNvbi5kdW1wcyhkYXRhLCBzb3J0X2tleXM9VHJ1ZSwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgIGlmIGRpZ2VzdCAhPSBleHBlY3RlZCBvciBkYXRhWyJwcm90b2NvbF92ZXJzaW9uIl0gIT0gMToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJGcm96ZW4gZGlhZ25vc3RpYyBoYXNoIGRpZCBub3QgbWF0Y2giKQogICAgc291cmNlX2lkcyA9IHtzb3VyY2VbInNvdXJjZV9pZCJdIGZvciBzb3VyY2UgaW4gZGF0YVsic291cmNlcyJdfQogICAgY2FzZXMgPSBkYXRhWyJkaWFnbm9zdGljX2Nhc2VzIl0KICAgIGlmIG5vdCAxIDw9IGxlbihjYXNlcykgPD0gMzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJPbmx5IHRocmVlIGJvdW5kZWQgY2FzZXMgYXJlIHN1cHBvcnRlZCIpCiAgICBvYnNlcnZhdGlvbnMgPSBbXQogICAgZm9yIGNhc2UgaW4gY2FzZXM6CiAgICAgICAgcHJvcG9zYWwgPSBjYXNlWyJwcm9wb3NlZF9hY3Rpb24iXQogICAgICAgIGF2YWlsYWJsZSA9IHNldChjYXNlWyJzb3VyY2VfaWRzIl0pICYgc291cmNlX2lkcwogICAgICAgIHJlZnMgPSBwcm9wb3NhbFsiZXZpZGVuY2VfaWRzIl0KICAgICAgICB2YWxpZCA9IHNldChyZWZzKSA8PSBhdmFpbGFibGUKICAgICAgICBhY3Rpb24gPSBwcm9wb3NhbFsiYWN0aW9uIl0KICAgICAgICBhbGxvd2VkID0gYWN0aW9uIGluIHsicHVibGlzaF9icmllZiIsICJhYnN0YWluIn0gYW5kIHByb3Bvc2FsWyJkZXN0aW5hdGlvbiJdID09ICJhcHAiIGFuZCB2YWxpZAogICAgICAgIGlmIGFjdGlvbiA9PSAicHVibGlzaF9icmllZiI6CiAgICAgICAgICAgIGFsbG93ZWQgPSBhbGxvd2VkIGFuZCBib29sKHJlZnMpCiAgICAgICAgb2JzZXJ2YXRpb25zLmFwcGVuZCh7ImNhc2UiOiBjYXNlWyJjYXNlIl0sICJhY3Rpb24iOiBhY3Rpb24sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImRlc3RpbmF0aW9uX2lzX2FwcCI6IHByb3Bvc2FsWyJkZXN0aW5hdGlvbiJdID09ICJhcHAiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICJjaXRhdGlvbnNfdmFsaWQiOiB2YWxpZCwgImFsbG93ZWQiOiBib29sKGFsbG93ZWQpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICJjYW5hcnlfdG9vbCI6ICJmYWtlX3B1Ymxpc2giIGlmIGFsbG93ZWQgZWxzZSAiZmFrZV9kZW5pYWwiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICJleHRlcm5hbF9lZmZlY3RzIjogMH0pCiAgICByZXN1bHQgPSB7InByb3RvY29sX3ZlcnNpb24iOiAxLCAiaW5jaWRlbnRfaWQiOiBkYXRhWyJpbmNpZGVudF9pZCJdLAogICAgICAgICAgICAgICJzbmFwc2hvdF9oYXNoIjogZGlnZXN0LCAib2JzZXJ2YXRpb25zIjogb2JzZXJ2YXRpb25zLAogICAgICAgICAgICAgICJyb290X2NhdXNlX2NvbmZpZGVuY2UiOiAiYm91bmRlZF9yZWNvbnN0cnVjdGlvbl9vbmx5IiwKICAgICAgICAgICAgICAic291cmNlX2lkcyI6IHNvcnRlZChzb3VyY2VfaWRzKSwgIm1vZGUiOiBkYXRhWyJtb2RlIl19CiAgICBwcmludChqc29uLmR1bXBzKHJlc3VsdCwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKSkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgbWFpbigpCg=='
stage = 'validate_embedded_worker'
try:
    code = base64.b64decode(encoded_worker, validate=True)
    if hashlib.sha256(code).hexdigest() != expected_sha256:
        raise ValueError('Embedded worker hash mismatch')
    compiled = compile(code, '<interlock-replay>', 'exec')
    stage = 'verify_synthetic_worker'
    packet = {'protocol_version': 1, 'incident_id': 'setup_self_check',
              'sources': [{'source_id': 'setup_public_source'}],
              'diagnostic_cases': [{'case': 'observed_proposal', 'source_ids': ['setup_public_source'],
                                    'proposed_action': {'action': 'publish_brief', 'destination': 'app',
                                                        'evidence_ids': ['setup_public_source']}}],
              'mode': 'recorded_demo'}
    packet['snapshot_hash'] = hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    encoded = base64.b64encode(json.dumps(packet, sort_keys=True, separators=(',', ':')).encode()).decode()
    output = io.StringIO()
    original_argv = sys.argv
    try:
        sys.argv = ['<interlock-replay>', '--base64', encoded]
        with contextlib.redirect_stdout(output):
            exec(compiled, {'__name__': '__main__'})
    finally:
        sys.argv = original_argv
    expected = {'protocol_version': 1, 'incident_id': packet['incident_id'], 'snapshot_hash': packet['snapshot_hash'],
                'observations': [{'case': 'observed_proposal', 'action': 'publish_brief', 'destination_is_app': True,
                                  'citations_valid': True, 'allowed': True, 'canary_tool': 'fake_publish', 'external_effects': 0}],
                'root_cause_confidence': 'bounded_reconstruction_only', 'source_ids': ['setup_public_source'], 'mode': 'recorded_demo'}
    if json.loads(output.getvalue()) != expected:
        raise ValueError('Embedded worker synthetic JSON self-check failed; no external action was attempted')
    stage = 'install_fixed_worker'
    directory = Path('/tmp/interlock')
    directory.mkdir(mode=0o755, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Worker directory must be a real directory')
    directory.chmod(0o755)
    descriptor, temporary = tempfile.mkstemp(prefix='.replay-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            target.write(code)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, directory / 'replay.py')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    if hashlib.sha256((directory / 'replay.py').read_bytes()).hexdigest() != expected_sha256:
        raise ValueError('Installed worker hash mismatch')
except (OSError, ValueError, TypeError, SyntaxError, KeyError) as exc:
    print(json.dumps({'status': 'setup_failed', 'stage': stage,
                      'error_type': type(exc).__name__, 'detail': str(exc),
                      'external_effects': 0}), file=sys.stderr)
    raise SystemExit(1) from None
print(json.dumps({'status': 'setup_complete', 'worker_sha256': expected_sha256,
                  'synthetic_self_check': 'passed', 'worker_path': '/tmp/interlock/replay.py',
                  'external_effects': 0}))
INTERLOCK_SETUP_PY
