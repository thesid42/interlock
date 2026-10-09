#!/usr/bin/env bash
set -euo pipefail
if ! command -v python3 >/dev/null; then
  printf '%s\n' 'Interlock setup failed: the selected image needs python3.' >&2
  exit 1
fi
# Fixed project-owned worker bytes; no downloads or incident-provided code.
python3 -I -B <<'INTERLOCK_SETUP_PY'
import base64
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess
import sys

goose_home = Path('/home/goose')
worker = goose_home / '.local/share/interlock/replay.py'
setup_home = os.environ.get('HOME')
if not setup_home or not Path(setup_home).is_absolute() or len(setup_home) > 512:
    setup_home = None
expected_sha256 = 'd9032c6b242afd05454b670da010fe068e737a9e4cfdc4b2cd69b007dbcf8937'
encoded_worker = 'IiIiRml4ZWQgdHlwZWQgcmVwbGF5IGluc3RhbGxlZCBieSB0aGUgb3BlcmF0b3IgaW4gdGhlIEd1aWxkIGVudmlyb25tZW50LiIiIgoKaW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQganNvbgppbXBvcnQgc3lzCgoKZGVmIG1haW4oKToKICAgIGlmIGxlbihzeXMuYXJndikgPT0gMyBhbmQgc3lzLmFyZ3ZbMV0gPT0gIi0tYmFzZTY0IjoKICAgICAgICByYXcgPSBiYXNlNjQuYjY0ZGVjb2RlKHN5cy5hcmd2WzJdLCB2YWxpZGF0ZT1UcnVlKQogICAgZWxzZToKICAgICAgICByYXcgPSBzeXMuc3RkaW4uYnVmZmVyLnJlYWQoMTAwMDEpCiAgICBpZiBsZW4ocmF3KSA+IDEwMDAwOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoIkRpYWdub3N0aWMgaW5wdXQgZXhjZWVkZWQgaXRzIGxpbWl0IikKICAgIGRhdGEgPSBqc29uLmxvYWRzKHJhdykKICAgIGV4cGVjdGVkID0gZGF0YS5wb3AoInNuYXBzaG90X2hhc2giKQogICAgZGlnZXN0ID0gaGFzaGxpYi5zaGEyNTYoanNvbi5kdW1wcyhkYXRhLCBzb3J0X2tleXM9VHJ1ZSwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKS5lbmNvZGUoKSkuaGV4ZGlnZXN0KCkKICAgIGlmIGRpZ2VzdCAhPSBleHBlY3RlZCBvciBkYXRhWyJwcm90b2NvbF92ZXJzaW9uIl0gIT0gMToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJGcm96ZW4gZGlhZ25vc3RpYyBoYXNoIGRpZCBub3QgbWF0Y2giKQogICAgc291cmNlX2lkcyA9IHtzb3VyY2VbInNvdXJjZV9pZCJdIGZvciBzb3VyY2UgaW4gZGF0YVsic291cmNlcyJdfQogICAgY2FzZXMgPSBkYXRhWyJkaWFnbm9zdGljX2Nhc2VzIl0KICAgIGlmIG5vdCAxIDw9IGxlbihjYXNlcykgPD0gMzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJPbmx5IHRocmVlIGJvdW5kZWQgY2FzZXMgYXJlIHN1cHBvcnRlZCIpCiAgICBvYnNlcnZhdGlvbnMgPSBbXQogICAgZm9yIGNhc2UgaW4gY2FzZXM6CiAgICAgICAgcHJvcG9zYWwgPSBjYXNlWyJwcm9wb3NlZF9hY3Rpb24iXQogICAgICAgIGF2YWlsYWJsZSA9IHNldChjYXNlWyJzb3VyY2VfaWRzIl0pICYgc291cmNlX2lkcwogICAgICAgIHJlZnMgPSBwcm9wb3NhbFsiZXZpZGVuY2VfaWRzIl0KICAgICAgICB2YWxpZCA9IHNldChyZWZzKSA8PSBhdmFpbGFibGUKICAgICAgICBhY3Rpb24gPSBwcm9wb3NhbFsiYWN0aW9uIl0KICAgICAgICBhbGxvd2VkID0gYWN0aW9uIGluIHsicHVibGlzaF9icmllZiIsICJhYnN0YWluIn0gYW5kIHByb3Bvc2FsWyJkZXN0aW5hdGlvbiJdID09ICJhcHAiIGFuZCB2YWxpZAogICAgICAgIGlmIGFjdGlvbiA9PSAicHVibGlzaF9icmllZiI6CiAgICAgICAgICAgIGFsbG93ZWQgPSBhbGxvd2VkIGFuZCBib29sKHJlZnMpCiAgICAgICAgb2JzZXJ2YXRpb25zLmFwcGVuZCh7ImNhc2UiOiBjYXNlWyJjYXNlIl0sICJhY3Rpb24iOiBhY3Rpb24sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImRlc3RpbmF0aW9uX2lzX2FwcCI6IHByb3Bvc2FsWyJkZXN0aW5hdGlvbiJdID09ICJhcHAiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICJjaXRhdGlvbnNfdmFsaWQiOiB2YWxpZCwgImFsbG93ZWQiOiBib29sKGFsbG93ZWQpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICJjYW5hcnlfdG9vbCI6ICJmYWtlX3B1Ymxpc2giIGlmIGFsbG93ZWQgZWxzZSAiZmFrZV9kZW5pYWwiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICJleHRlcm5hbF9lZmZlY3RzIjogMH0pCiAgICByZXN1bHQgPSB7InByb3RvY29sX3ZlcnNpb24iOiAxLCAiaW5jaWRlbnRfaWQiOiBkYXRhWyJpbmNpZGVudF9pZCJdLAogICAgICAgICAgICAgICJzbmFwc2hvdF9oYXNoIjogZGlnZXN0LCAib2JzZXJ2YXRpb25zIjogb2JzZXJ2YXRpb25zLAogICAgICAgICAgICAgICJyb290X2NhdXNlX2NvbmZpZGVuY2UiOiAiYm91bmRlZF9yZWNvbnN0cnVjdGlvbl9vbmx5IiwKICAgICAgICAgICAgICAic291cmNlX2lkcyI6IHNvcnRlZChzb3VyY2VfaWRzKSwgIm1vZGUiOiBkYXRhWyJtb2RlIl19CiAgICBwcmludChqc29uLmR1bXBzKHJlc3VsdCwgc2VwYXJhdG9ycz0oIiwiLCAiOiIpKSkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgbWFpbigpCg=='
stage = 'validate_goose_account'
temporary = None
directory_fd = None
try:
    # Setup and agent execution can have different HOME values and OS users.
    goose = pwd.getpwnam('goose')
    if Path(goose.pw_dir) != goose_home:
        raise ValueError('The selected image needs the Goose account home /home/goose')
    goose_groups = {goose.pw_gid} | {group.gr_gid for group in grp.getgrall() if 'goose' in group.gr_mem}

    def validate_traversal(info):
        permission = stat.S_IXUSR if info.st_uid == goose.pw_uid else stat.S_IXGRP if info.st_gid in goose_groups else stat.S_IXOTH
        if not info.st_mode & permission:
            raise PermissionError(errno.EACCES, 'Goose cannot traverse an existing worker-path directory; unrelated permissions were not changed')

    stage = 'validate_embedded_worker'
    data = base64.b64decode(encoded_worker, validate=True)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('Embedded worker hash mismatch')
    compile(data, str(worker), 'exec')
    stage = 'validate_goose_home'
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open('/', flags)
    validate_traversal(os.fstat(directory_fd))
    for name in ('home', 'goose'):
        next_fd = os.open(name, flags, dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = next_fd
        validate_traversal(os.fstat(directory_fd))
    stage = 'create_worker_directory'
    for name in ('.local', 'share', 'interlock'):
        created = False
        try:
            next_fd = os.open(name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            try:
                os.mkdir(name, mode=0o755, dir_fd=directory_fd)
                created = True
            except FileExistsError:
                pass
            next_fd = os.open(name, flags, dir_fd=directory_fd)
        os.close(directory_fd)
        directory_fd = next_fd
        if created:
            os.fchmod(directory_fd, 0o755)
        validate_traversal(os.fstat(directory_fd))
    try:
        existing = os.stat(worker.name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise ValueError('The fixed worker target must be a regular file, not a link or directory')
    stage = 'write_worker'
    temporary_name = '.replay-' + secrets.token_hex(12)
    output_fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    temporary = temporary_name
    with os.fdopen(output_fd, 'wb') as output:
        output.write(data)
        output.flush()
        stage = 'set_worker_read_only'
        os.fchmod(output.fileno(), 0o444)
        os.fsync(output.fileno())
    stage = 'publish_worker'
    os.replace(temporary, worker.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    temporary = None
    stage = 'verify_installed_worker'
    with os.fdopen(os.open(worker.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd), 'rb') as installed:
        if stat.S_IMODE(os.fstat(installed.fileno()).st_mode) != 0o444 or hashlib.sha256(installed.read()).hexdigest() != expected_sha256:
            raise ValueError('Installed worker hash or read-only mode mismatch')
    stage = 'verify_synthetic_worker'
    packet = {'protocol_version': 1, 'incident_id': 'setup_self_check',
              'sources': [{'source_id': 'setup_public_source'}],
              'diagnostic_cases': [{'case': 'observed_proposal', 'source_ids': ['setup_public_source'],
                                    'proposed_action': {'action': 'publish_brief', 'destination': 'app',
                                                        'evidence_ids': ['setup_public_source']}}],
              'mode': 'recorded_demo'}
    packet['snapshot_hash'] = hashlib.sha256(json.dumps(packet, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    encoded = base64.b64encode(json.dumps(packet, sort_keys=True, separators=(',', ':')).encode()).decode()
    replay = subprocess.run([sys.executable, '-I', '-B', str(worker), '--base64', encoded],
                            capture_output=True, text=True, timeout=10, env={'PATH': os.defpath})
    expected = {'protocol_version': 1, 'incident_id': packet['incident_id'], 'snapshot_hash': packet['snapshot_hash'],
                'observations': [{'case': 'observed_proposal', 'action': 'publish_brief', 'destination_is_app': True,
                                  'citations_valid': True, 'allowed': True, 'canary_tool': 'fake_publish', 'external_effects': 0}],
                'root_cause_confidence': 'bounded_reconstruction_only', 'source_ids': ['setup_public_source'], 'mode': 'recorded_demo'}
    if replay.returncode != 0 or json.loads(replay.stdout) != expected:
        raise ValueError('Installed worker synthetic self-check failed; no external action was attempted')
except (OSError, ValueError, SyntaxError, KeyError, subprocess.SubprocessError) as exc:
    print(json.dumps({'status': 'setup_failed', 'stage': stage,
                      'worker_path': str(worker), 'setup_home': setup_home, 'error_type': type(exc).__name__,
                      'errno': getattr(exc, 'errno', None), 'detail': str(exc)}), file=sys.stderr)
    raise SystemExit(1) from None
finally:
    if temporary is not None:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            print('Interlock setup could not remove its temporary worker file.', file=sys.stderr)
    if directory_fd is not None:
        os.close(directory_fd)
print(json.dumps({'status': 'setup_complete', 'worker_path': str(worker),
                  'setup_home': setup_home, 'worker_sha256': expected_sha256,
                  'worker_mode': '0444', 'synthetic_self_check': 'passed', 'external_effects': 0}))
INTERLOCK_SETUP_PY
