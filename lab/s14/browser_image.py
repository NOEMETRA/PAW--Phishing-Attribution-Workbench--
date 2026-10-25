"""Explicit root construction of a locally derived trusted offline browser image.

The administrator must first verify signatures, signed indices and all package
hashes, then approve that exact manifest digest. No email/candidate can authorize
this operation. Packages are installed only in the no-NIC preparation guest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
import traceback
import uuid

HERE = Path(__file__).resolve().parent; sys.path.insert(0, str(HERE))
import hash_authorization as platform
from browser_vm import BrowserVM, BROWSER_BASE, BROWSER_META
from benign_guest_validation import BASE, digest, guard_fingerprint

GOOGLE_PRIMARY = 'EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796'
CONTROL = Path('/var/lib/paw-s14/control')
RUNS = Path('/var/lib/libvirt/images/paw-s14/runs')


def require(value, reason):
    if not value: raise ValueError(reason)


def validate_packages(raw, expected):
    require(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected) and len(raw) <= 1024**2 and
            hashlib.sha256(raw).hexdigest() == expected, 'approved_package_manifest_digest')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate_package_manifest_key'); value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    require(raw == platform.fs.canonical(value), 'canonical_package_manifest')
    require(value['schema'] == 'paw-browser-verified-packages-v1' and type(value['host_installs']) is int and value['host_installs'] == 0 and
            value['google_primary_fingerprint'] == GOOGLE_PRIMARY and type(value['packages']) is list and
            1 <= len(value['packages']) <= 512, 'verified_package_manifest_scope')
    packages = []; names = set()
    for row in value['packages']:
        require(type(row) is dict and set(row) == {'file', 'package', 'version', 'architecture', 'bytes', 'sha256', 'verified_signed_indices'} and
                type(row['package']) is str and re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,128}', row['package']) and
                type(row['version']) is str and re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,200}', row['version']) and row['architecture'] in {'amd64', 'all'} and type(row['bytes']) is int and
                0 < row['bytes'] <= 256*1024**2 and type(row['file']) is str and
                re.fullmatch(r'[A-Za-z0-9+_.%:~=-]{1,200}\.deb', row['file']) and row['file'] not in names and
                type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) and
                type(row['verified_signed_indices']) is list and row['verified_signed_indices'], 'approved_package_shape')
        names.add(row['file']); packages.append({k: row[k] for k in ['file', 'package', 'version', 'architecture', 'bytes', 'sha256']})
    require(sum(v['bytes'] for v in packages) <= 1024**3 and
            sum(v['package'] == 'google-chrome-stable' for v in packages) == 1 and
            any(v['package'] == 'apparmor' for v in packages), 'approved_browser_dependency_closure')
    return packages


def copy_approved(source, target, expected, size):
    """Single opened descriptor, stream hash before granting any guest access."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd); require(stat.S_ISREG(info.st_mode) and info.st_size == size, 'package_regular_file_size')
        h = hashlib.sha256(); count = 0
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(target_fd, 'wb') as output:
            while True:
                raw = os.read(fd, 1024**2)
                if not raw: break
                count += len(raw); require(count <= size, 'package_changed_size'); h.update(raw); output.write(raw)
            output.flush(); os.fsync(output.fileno())
        after = os.fstat(fd)
        require(count == size and h.hexdigest() == expected and
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'package_copy_digest_or_change')
        target.chmod(0o444)
    finally: os.close(fd)


def validate_builder_shutdown(result, expected_uuid):
    require(type(result) is dict and result.get('reason') == 'guest_shutdown' and
            result.get('connection_closed') is True and result.get('guest_shutdown_event') is True and
            result.get('vm_uuid') == expected_uuid, 'builder_requires_successful_guest_shutdown')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True); parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--export', type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and Path('/proc/self/attr/current').read_text().strip() == 'unconfined', 'explicit_root_PID1_builder_required')
    require(not BROWSER_BASE.exists() and not BROWSER_META.exists(), 'existing_browser_image_must_not_be_overwritten')
    from verify_granted_offline import regular
    raw = regular(args.manifest, 1024**2); packages = validate_packages(raw, args.expected_sha256)
    require(shutil.disk_usage(BASE.parent).free >= 10*1024**3, 'browser_build_disk_admission')
    with platform.fs.execution_lock():
        context = platform.capture(); platform.validate_context(context); source_freeze = context['host']['source_hashes']
        for parent in [CONTROL, RUNS, BASE.parent]:
            with platform.fs.root_directory(parent): pass
        identifier = uuid.uuid4().hex; output = CONTROL / ('browser-image-' + identifier)
        media_dir = RUNS / str(uuid.uuid4()); media_dir.mkdir(mode=0o755)
        tree = media_dir / 'trusted-packages'; tree.mkdir(mode=0o700); (tree / 'packages').mkdir(mode=0o700)
        for package in packages:
            copy_approved(args.manifest.parent / 'apt/archives' / package['file'], tree / 'packages' / package['file'], package['sha256'], package['bytes'])
        manifest = {'schema': 'paw-browser-build-packages-v1', 'foundation_sha256': platform.fs.IMAGE_SHA256,
                    'approved_verified_manifest_sha256': args.expected_sha256, 'packages': packages}
        manifest_raw = platform.fs.canonical(manifest); (tree / 'manifest.json').write_bytes(manifest_raw)
        iso = media_dir / 'packages.iso'
        import subprocess
        subprocess.run(['/usr/bin/genisoimage', '-quiet', '-output', str(iso), '-volid', 'PAWBROWSERPKG', '-joliet', '-rock', str(tree)], check=True, timeout=120)
        iso.chmod(0o444)
        gate = BrowserVM(argparse.Namespace(output=output), phase='build', media=iso,
                         seed_config={'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest()})
        gate.canary = output / 'host-owned-canary.bin'; gate.canary.write_bytes(os.urandom(32)); canary = digest(gate.canary)
        before = gate.snapshot_host(); info = None; vm = None
        gate.report.update(package_manifest_sha256=args.expected_sha256, pre_context=context, actual_real_samples=0,
                           source_freeze=source_freeze, package_count=len(packages), local_administrative_approval=True)
        try:
            print('Starting trusted offline browser image provisioning, no NIC or real sample.', flush=True)
            vm = gate.start('trusted-browser-build')
            info = vm['channel'].call('provision', seconds=650)
            require(info['schema'] == 'paw-browser-image-guest-v1' and info['approved_packages'] == len(packages) and
                    info['network_interfaces'] == ['lo'] and info['kernel_release'] == '6.8.0-147-generic' and
                    all(info['probe'][k] is True for k in ['renderer_seen', 'renderer_nnp', 'renderer_seccomp', 'all_uids_nonroot', 'renderer_pid_namespace']) and
                    info['cpu_sensitive_features_absent'] is True and info['probe']['title'] == 'PAW-BROWSER-PROBE', 'trusted_image_provisioning_or_sandbox_probe')
            require(vm['channel'].call('shutdown', seconds=10) == {'shutdown_requested': True}, 'image_shutdown_ack')
            deadline = time.monotonic() + 45
            while not gate.absent(vm) and time.monotonic() < deadline: time.sleep(.1)
            require(gate.absent(vm), 'graceful_builder_shutdown_not_observed')
            vm['owner'].wait(timeout=3)
            with platform.fs.root_directory(output) as fd:
                owner_result = json.loads(platform.fs.read(fd, Path(vm['owner_result_path']).name, 65536))
            validate_builder_shutdown(owner_result, vm['node']['uuid'])
            gate.report['graceful_shutdown_evidence'] = owner_result
            gate.stop(vm); vm = None
            require(before == gate.snapshot_host() and digest(BASE) == platform.fs.IMAGE_SHA256 and digest(gate.canary) == canary and
                    platform.capture() == context, 'browser_build_host_or_foundation_changed')
            overlay = gate.report['vms'][0]
            node = gate.last_build_node
            temporary = BASE.parent / ('.browser-image-' + identifier)
            copy_approved(node['overlay'], temporary, overlay['overlay_sha256_after_stop'], node['overlay'].stat().st_size)
            os.chown(temporary, 0, 0)
            # link is atomic and refuses any existing target; historical images are immutable.
            os.link(temporary, BROWSER_BASE); temporary.unlink()
            certificate = {'schema': 'paw-s14-browser-image-v1', 'image_sha256': digest(BROWSER_BASE),
                'foundation_sha256': platform.fs.IMAGE_SHA256, 'backing_file': str(BASE),
                'approved_packages_manifest_sha256': args.expected_sha256, 'built_at': int(time.time()),
                'build_sources': source_freeze, 'guest': info,
                'trust': 'local root-derived image from administrator-approved signature/index/hash-verified packages; not vendor-signed custom image or remote attestation'}
            with platform.fs.root_directory(BASE.parent) as fd: platform.fs.exclusive(fd, BROWSER_META.name, platform.fs.canonical(certificate))
            gate.report.update(result='PASS', browser_certificate=certificate, host_restored=True, base_unchanged=True,
                               host_canary_unchanged=True, writers_stopped=True, post_context=platform.capture())
        except Exception as error:
            gate.report.update(result='FAIL', error=str(error), traceback=traceback.format_exc()); print(gate.report['traceback'], flush=True)
        finally:
            try:
                if gate.active_vm: gate.stop(gate.active_vm)
                require(not gate.connection.listAllDomains(0) and before == gate.snapshot_host(), 'browser_builder_cleanup')
            except Exception as error: gate.report.update(result='FAIL', cleanup_error=str(error))
            gate.connection.close(); (output / 'results.json').write_text(json.dumps(gate.report, indent=2) + '\n')
            args.export.mkdir(mode=0o700, parents=True, exist_ok=False)
            for path in output.iterdir():
                if path.is_file() and path.suffix in {'.json', '.xml', '.log'}: shutil.copyfile(path, args.export / path.name)
                elif path.is_dir() and path.name == 'sources': shutil.copytree(path, args.export / path.name)
            for path in [args.export, *args.export.rglob('*')]: os.chown(path, 1000, 1000)
        print(json.dumps({'result': gate.report['result'], 'export': str(args.export), 'browser_image': str(BROWSER_BASE), 'real_samples': 0}), flush=True)
        require(gate.report['result'] == 'PASS', 'browser_image_build_failed')


if __name__ == '__main__': main()
