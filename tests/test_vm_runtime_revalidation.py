"""Inert runtime tests: all administrative commands and libvirt are replaced."""
import copy
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lab/s14'))
import vm_runtime_revalidation as runtime

GOOD = {'guard': 'a'*64, 'guard_service': {'LoadState': 'loaded', 'ActiveState': 'active'},
    'slice_properties': {'LoadState': 'loaded', **runtime.SLICE}, 'qemu_pids': [], 'namespaces': [],
    'tcp_sockets': {'libvirtd-tcp.socket': 'inactive', 'libvirtd-tls.socket': 'inactive'},
    'domain_definitions': [], 'autostart': [], 'hooks': [], 'daemon_config_sha256': 'b'*64}


class Runtime(unittest.TestCase):
    def network_snapshot(self, rules):
        def output(argv, **kwargs):
            if argv[0] == '/usr/sbin/nft': return json.dumps(rules).encode()
            self.assertEqual(argv, ['/usr/sbin/ip', '-j', 'route']); return b'[]'
        with mock.patch.object(runtime.subprocess, 'check_output', side_effect=output), \
             mock.patch.object(Path, 'iterdir', side_effect=lambda: iter([Path('/sys/class/net/lo')])):
            return runtime.network_state()

    def test_full_ruleset_scalar_lists_ranges_and_map_pairs_are_observed(self):
        rules = {'nftables': [{'metainfo': {'version': 'owned'}}, {'set': {
            'family': 'inet', 'table': 'owned', 'name': 'ports', 'type': 'inet_service',
            'elem': [80, 443, {'range': [1000, 1010]}]}}, {'map': {'elem': [['tcp', 80], ['udp', 53]]}}]}
        value = self.network_snapshot(rules)
        self.assertEqual(len(value['nft_sha256']), 64)
        self.assertEqual(value['interfaces'], ['lo']); self.assertEqual(value['routes'], [])

    def test_full_ruleset_volatile_fields_ignore_only_counters_handles_and_metadata(self):
        rules = {'nftables': [{'metainfo': {'version': 'owned'}}, {'rule': {'handle': 7,
                 'expr': [{'counter': {'packets': 1, 'bytes': 64}}, {'match': {'right': [80, 443]}}]}}]}
        other = copy.deepcopy(rules); other['nftables'][0]['metainfo']['version'] = 'other'
        other['nftables'][1]['rule']['handle'] = 88
        other['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 999
        self.assertEqual(self.network_snapshot(rules), self.network_snapshot(other))
        other['nftables'][1]['rule']['expr'][1]['match']['right'] = [80, 444]
        self.assertNotEqual(self.network_snapshot(rules)['nft_sha256'], self.network_snapshot(other)['nft_sha256'])

    def test_full_ruleset_scalar_metadata_spelling_is_preserved(self):
        rules = {'nftables': [{'set': {'elem': ['lo', 'metainfo']}}]}
        other = {'nftables': [{'set': {'elem': ['lo']}}]}
        self.assertNotEqual(self.network_snapshot(rules)['nft_sha256'], self.network_snapshot(other)['nft_sha256'])

    def test_fixed_observation_passes(self):
        self.assertEqual(runtime.validate_snapshot(copy.deepcopy(GOOD)), GOOD)

    def test_guard_missing_inactive_or_wrong_hash_refuses(self):
        for value in [None, '0'*63, 'z'*64]:
            candidate = copy.deepcopy(GOOD); candidate['guard'] = value
            with self.assertRaises(ValueError): runtime.validate_snapshot(candidate)
        candidate = copy.deepcopy(GOOD); candidate['guard_service']['ActiveState'] = 'inactive'
        with self.assertRaises(ValueError): runtime.validate_snapshot(candidate)

    def test_budget_expansion_or_swap_refuses(self):
        for key, value in [('MemoryMax', str(4*1024**3)), ('MemorySwapMax', 'infinity'), ('TasksMax', '256')]:
            candidate = copy.deepcopy(GOOD); candidate['slice_properties'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): runtime.validate_snapshot(candidate)

    def test_qemu_foreign_namespace_domain_autostart_or_hook_refuses(self):
        for key, value in [('qemu_pids', [123]), ('namespaces', ['owned-but-active']),
                           ('domain_definitions', ['other.xml']), ('autostart', ['default.xml']), ('hooks', ['qemu'])]:
            candidate = copy.deepcopy(GOOD); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): runtime.validate_snapshot(candidate)

    def test_tcp_or_tls_libvirt_refuses(self):
        for key in GOOD['tcp_sockets']:
            candidate = copy.deepcopy(GOOD); candidate['tcp_sockets'][key] = 'active'
            with self.assertRaises(ValueError): runtime.validate_snapshot(candidate)

    def test_unknown_unit_never_invokes_systemd(self):
        with mock.patch.object(runtime.subprocess, 'check_output') as run:
            with self.assertRaises(ValueError): runtime.properties('arbitrary.service', ['ActiveState'])
        run.assert_not_called()

    def test_stock_qemu_with_renamed_comm_still_counts_as_busy(self):
        info = SimpleNamespace(st_dev=1, st_ino=123)
        with mock.patch.object(Path, 'iterdir', return_value=iter([Path('/proc/77')])), \
             mock.patch.object(Path, 'stat', return_value=info), \
             mock.patch.object(Path, 'read_text', return_value='renamed-process'), \
             mock.patch.object(Path, 'readlink', return_value=Path('/usr/bin/renamed')):
            self.assertEqual(runtime.process_inventory(), [77])

    def configuration(self, *, changed=None, environment=b'# no override\n', guard=b'[Unit]\n'):
        config = {'ExecStart': '{ path=/usr/sbin/libvirtd ; argv[]=/usr/sbin/libvirtd $LIBVIRTD_ARGS ; ignore_errors=no ; pid=0 }',
            'Environment': '"LIBVIRTD_ARGS=--timeout 120"', 'EnvironmentFiles': '/etc/default/libvirtd (ignore_errors=yes)',
            'FragmentPath': '/usr/lib/systemd/system/libvirtd.service',
            'DropInPaths': '/etc/systemd/system/libvirtd.service.d/paw-s14-guard.conf'}
        if changed: config.update(changed)
        def read(fd, name, maximum):
            return environment if name == 'libvirtd' else guard if name == 'paw-s14-guard.conf' else b'owned inert unit bytes'
        fs = SimpleNamespace(root_directory=lambda path: nullcontext(str(path)), read=read,
                             digest=lambda raw: hashlib.sha256(raw).hexdigest())
        with mock.patch.dict(sys.modules, {'one_use_authorization': fs}), \
             mock.patch.object(runtime, 'properties', return_value=config), \
             mock.patch.object(Path, 'read_bytes', return_value=b'[Unit]\n'):
            return runtime.daemon_configuration()

    def test_default_configuration_has_stable_digest(self):
        self.assertEqual(len(self.configuration()), 64)
        self.assertEqual(self.configuration(environment=b'LIBVIRTD_ARGS="--timeout 120"\n'),
                         self.configuration(environment=b'LIBVIRTD_ARGS="--timeout 120"\n'))

    def test_daemon_listen_or_other_environment_assignment_refuses(self):
        for raw in [b'LIBVIRTD_ARGS="--listen"', b'LD_PRELOAD=/tmp/unknown.so', b'PATH=/tmp']:
            with self.subTest(raw=raw), self.assertRaises(ValueError): self.configuration(environment=raw)

    def test_unknown_daemon_command_environment_file_or_dropin_refuses(self):
        for key, value in [('ExecStart', '{ path=/bin/sh ; argv[]=/bin/sh ; }'),
                           ('Environment', '"LIBVIRTD_ARGS=--listen"'), ('EnvironmentFiles', '/tmp/env'),
                           ('DropInPaths', '/etc/systemd/system/libvirtd.service.d/custom.conf')]:
            with self.subTest(key=key), self.assertRaises(ValueError): self.configuration(changed={key: value})

    def test_guard_dependency_must_match_reviewed_bytes(self):
        with self.assertRaises(ValueError): self.configuration(guard=b'[Unit]\nAfter=network.target\n')

    def exercise(self, *, active=False, change=False, network_active=False, domains=False, failed_start=False):
        commands = []; snapshot = copy.deepcopy(GOOD)
        units = {unit: 'active' if active else 'inactive' for unit in runtime.UNITS}
        def observe():
            result = copy.deepcopy(snapshot)
            if change and commands: result['guard'] = 'c'*64
            return result
        def properties(unit, names):
            values = {'LoadState': 'loaded', 'ActiveState': units[unit]}
            return {name: values[name] for name in names}
        def start(argv, **kwargs):
            self.assertEqual(argv[:2], ['/usr/bin/systemctl', 'start'])
            self.assertEqual(len(argv), 3); self.assertIn(argv[2], runtime.UNITS)
            commands.append(argv)
            if failed_start: raise subprocess.CalledProcessError(1, argv)
            units[argv[2]] = 'active'
        connection = SimpleNamespace(listAllDomains=lambda flags: ['foreign'] if domains else [],
            listAllNetworks=lambda flags: [SimpleNamespace(isActive=lambda: network_active,
                autostart=lambda: False, name=lambda: 'inactive-owned-definition')], close=mock.Mock())
        fs = SimpleNamespace(execution_lock=nullcontext, digest=lambda raw: hashlib.sha256(raw).hexdigest())
        host = SimpleNamespace(capture=lambda: {'host': 'inert'}, validate_context=lambda value: None)
        browser = SimpleNamespace(capture=lambda: {'browser': 'inert'}, validate_context=lambda value: None,
                                  canonical=lambda value: str(value).encode())
        libvirt = SimpleNamespace(registerErrorHandler=lambda *a: None, open=lambda uri: connection)
        modules = {'one_use_authorization': fs, 'hash_authorization': host, 'browser_authorization': browser, 'libvirt': libvirt}
        with mock.patch.dict(sys.modules, modules), mock.patch.object(runtime.os, 'geteuid', return_value=0), \
             mock.patch.object(Path, 'read_text', return_value='unconfined'), \
             mock.patch.object(runtime, 'snapshot', side_effect=observe), \
             mock.patch.object(runtime, 'network_state', return_value={'unchanged': True}), \
             mock.patch.object(runtime, 'properties', side_effect=properties), \
             mock.patch.object(runtime.subprocess, 'run', side_effect=start):
            try: result = runtime.revalidate()
            except Exception as error: return error, commands, connection
        return result, commands, connection

    def test_fixed_inactive_units_only_and_no_guest_actions(self):
        result, commands, connection = self.exercise()
        self.assertEqual(result['result'], 'PASS'); self.assertFalse(result['vm_started'])
        self.assertEqual(commands, [['/usr/bin/systemctl', 'start', unit] for unit in runtime.UNITS])
        self.assertEqual(result['before'], result['after']); connection.close.assert_called_once()
        self.assertFalse(result['i08_installed']); self.assertFalse(result['production_grants_enabled'])

    def test_actual_runtime_record_roundtrips_through_protected_state_decoder(self):
        import vm_operator_host as host
        value, _, _ = self.exercise()
        record = {'result': 'PASS', 'job': 'a'*32, 'recipe': 'vm-acceptance-v1',
                  'release_sha': 'b'*40, 'real_samples_executed': 0, 'runtime': value}
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                host.write_state(fd, 'result.json', record)
                # Ordinary temporary files substitute only the required owner;
                # serialization, scalar/depth limits, mode and I/O are real.
                with mock.patch.object(host, 'ROOT_UID', os.getuid()):
                    actual = host.private_json(fd, 'result.json')
            finally: os.close(fd)
        self.assertEqual(actual, record)
        self.assertIs(type(actual['runtime']['elapsed_milliseconds']), int)
        self.assertGreaterEqual(actual['runtime']['elapsed_milliseconds'], 0)

    def test_already_active_units_do_not_restart(self):
        result, commands, _ = self.exercise(active=True)
        self.assertEqual(result['result'], 'PASS'); self.assertEqual(commands, [])

    def test_reobserve_guard_before_second_fixed_start(self):
        result, commands, _ = self.exercise(change=True)
        self.assertIsInstance(result, ValueError); self.assertIn('prestart_changed', str(result))
        self.assertEqual(commands, [['/usr/bin/systemctl', 'start', 'machine-paws14.slice']])

    def test_foreign_domain_and_network_fail_without_readiness(self):
        for kwargs in [{'domains': True}, {'network_active': True}]:
            result, _, connection = self.exercise(**kwargs)
            self.assertIsInstance(result, ValueError); connection.close.assert_called_once()

    def test_start_failure_does_not_try_next_unit(self):
        result, commands, _ = self.exercise(failed_start=True)
        self.assertIsInstance(result, subprocess.CalledProcessError); self.assertEqual(len(commands), 1)

    def test_unprivileged_entry_refuses_before_context_or_start(self):
        with mock.patch.object(runtime.os, 'geteuid', return_value=1000), \
             mock.patch.object(runtime.subprocess, 'run') as run, self.assertRaises(ValueError):
            runtime.revalidate()
        run.assert_not_called()

    def test_owned_recipe_refuses_bad_job_release_and_non_snapshot_before_storage(self):
        for job, release in [('../out', 'a'*40), ('a'*32, '../release'), ('a'*32, 'a'*40)]:
            with mock.patch.object(runtime.os, 'geteuid', return_value=0), self.assertRaises(ValueError):
                runtime.run_owned(job, release)

    def owned(self, *, fail=False, unsafe=False):
        job, release = 'a'*32, 'b'*40; states = []; writes = []; published = []
        value = {'result': 'PASS', 'vm_started': unsafe, 'real_samples_executed': 0,
                 'production_grants_enabled': False, 'i08_installed': False}
        fs = SimpleNamespace(root_directory=lambda path: nullcontext(str(path)),
                             exclusive=lambda fd, name, raw: writes.append((fd, name, raw)))
        modules = {'one_use_authorization': fs,
            'reader_export': SimpleNamespace(publish_reader_tree=lambda path: published.append(path)),
            'vm_operator_host': SimpleNamespace(write_state=lambda fd, name, record: states.append(copy.deepcopy(record)))}
        with mock.patch.dict(sys.modules, modules), mock.patch.object(runtime.os, 'geteuid', return_value=0), \
             mock.patch.object(runtime, 'HERE', Path('/opt/paw-vm/releases')/release/'lab/s14'), \
             mock.patch.object(runtime, 'revalidate', **({'side_effect': ValueError('owned injected failure')} if fail else {'return_value': value})), \
             mock.patch.object(Path, 'mkdir'), mock.patch('builtins.print'):
            try: runtime.run_owned(job, release)
            except ValueError: pass
        return states, writes, published

    def test_owned_recipe_exports_root_reader_evidence_without_changing_entrypoint(self):
        states, writes, published = self.owned()
        self.assertEqual(states[-1]['result'], 'PASS'); self.assertEqual(states[-1]['recipe'], 'vm-acceptance-v1')
        self.assertEqual(len(writes), 1); self.assertEqual(writes[0][1], 'runtime.json')
        self.assertEqual(published, [Path('/var/lib/paw-vm-exports')/('a'*32)])

    def test_failed_or_unsafe_runtime_is_recorded_and_never_exported_as_pass(self):
        for kwargs in [{'fail': True}, {'unsafe': True}]:
            states, writes, published = self.owned(**kwargs)
            self.assertEqual(states[-1]['result'], 'FAIL'); self.assertEqual(writes, []); self.assertEqual(published, [])


if __name__ == '__main__': unittest.main()
