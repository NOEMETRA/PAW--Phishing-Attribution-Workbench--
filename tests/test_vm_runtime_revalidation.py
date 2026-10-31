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
import representation_producer
import hash_authorization as maintenance_auth
from test_hash_authorization import context as maintenance_context, maintenance

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

    def owned(self, *, fail=False, unsafe=False, fail_native=False, fail_javascript=False, fail_kernel=False, unsafe_kernel=False):
        import native_runtime
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
             mock.patch.object(runtime, 'refresh_maintenance', return_value={'result': 'PASS', 'vm_started': False}), \
             mock.patch('paw.core.owned_kernel_runtime.owned_validation', **({'side_effect': ValueError('owned kernel diagnostic failure')} if fail_kernel else {'return_value': dict(value, vm_started=unsafe_kernel)})), \
             mock.patch('representation_producer.previous_owned_failure', return_value={'source_result': 'FAIL', 'vm_started': False}), \
             mock.patch('representation_producer.previous_owned_javascript_failure', **({'side_effect': ValueError('owned JS diagnostic failure')} if fail_javascript else {'return_value': {'source_result': 'FAIL', 'vm_started': False}})), \
             mock.patch.object(native_runtime, 'previous_owned_native_failure', **({'side_effect': ValueError('owned native diagnostic failure')} if fail_native else {'return_value': {'source_result': 'FAIL', 'vm_started': False}})), \
             mock.patch.object(Path, 'mkdir'), mock.patch('builtins.print'):
            try: runtime.run_owned(job, release)
            except ValueError: pass
        return states, writes, published

    def test_owned_recipe_exports_root_reader_evidence_without_changing_entrypoint(self):
        states, writes, published = self.owned()
        self.assertEqual(states[-1]['result'], 'PASS'); self.assertEqual(states[-1]['recipe'], 'vm-acceptance-v1')
        self.assertEqual(len(writes), 1); self.assertEqual(writes[0][1], 'runtime.json')
        exported=json.loads(writes[0][2]);self.assertEqual(exported['previous_owned_native_failure'],{'source_result':'FAIL','vm_started':False})
        self.assertEqual(exported['previous_owned_javascript_failure'],{'source_result':'FAIL','vm_started':False})
        self.assertEqual(published, [Path('/var/lib/paw-vm-exports')/('a'*32)])

    def test_owned_kernel_failure_or_scope_expansion_cannot_publish_runtime_pass(self):
        for kwargs in [{'fail_kernel': True}, {'unsafe_kernel': True}]:
            states, writes, published = self.owned(**kwargs)
            self.assertEqual(states[-1]['result'], 'FAIL')
            self.assertEqual(writes, []); self.assertEqual(published, [])

    def test_failed_or_unsafe_runtime_is_recorded_and_never_exported_as_pass(self):
        for kwargs in [{'fail': True}, {'unsafe': True}, {'fail_native': True}, {'fail_javascript': True}]:
            states, writes, published = self.owned(**kwargs)
            self.assertEqual(states[-1]['result'], 'FAIL'); self.assertEqual(writes, []); self.assertEqual(published, [])


class MaintenanceTransition(unittest.TestCase):
    """Real maintenance validation with inert host data; no Root/VM authority."""
    def setUp(self):
        self.old_rows = b'libbrotli1:amd64\t1.2.0-3build1\nowned-other\t1\npython3-brotli\t1.2.0-3build1\n'
        self.new_rows = self.old_rows.replace(b'1.2.0-3build1', b'1.2.0-3ubuntu0.1')
        self.old_hash = self.inventory_hash(self.old_rows); self.new_hash = self.inventory_hash(self.new_rows)
        self.context = maintenance_context(); self.context['dpkg_inventory_sha256'] = self.old_hash
        self.previous = maintenance(self.context); self.context['dpkg_inventory_sha256'] = self.new_hash
        self.patches = [mock.patch.object(runtime, 'MAINTENANCE_PREVIOUS', maintenance_auth.digest(self.previous)),
            mock.patch.object(runtime, 'INVENTORY_PREVIOUS', self.old_hash),
            mock.patch.object(runtime, 'INVENTORY_BROTLI', self.new_hash)]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()

    @staticmethod
    def inventory_hash(rows): return maintenance_auth.digest(b'\n'.join(sorted(rows.splitlines()))+b'\n')

    def transition(self, *, previous=None, context=None, rows=None):
        return runtime.maintenance_transition(self.previous if previous is None else previous,
            self.context if context is None else context, self.new_rows if rows is None else rows)

    def test_stale_receipt_refuses_before_exact_transition_then_real_validator_accepts(self):
        with self.assertRaisesRegex(ValueError, 'maintenance_binding'):
            maintenance_auth.validate_maintenance(self.previous, self.context)
        result = self.transition(); receipt = maintenance_auth.validate_maintenance(result, self.context)
        self.assertEqual(receipt['dpkg_inventory_sha256'], self.new_hash)
        old = json.loads(self.previous)
        for key in set(old)-{'dpkg_inventory_sha256', 'review_notes'}: self.assertEqual(receipt[key], old[key])

    def test_old_unchanged_baseline_is_idempotent(self):
        context = dict(self.context, dpkg_inventory_sha256=self.old_hash)
        self.assertEqual(self.transition(context=context, rows=self.old_rows), self.previous)

    def test_receipt_tamper_or_wrong_protected_predecessor_refuses(self):
        with self.assertRaisesRegex(ValueError, 'previous_maintenance_digest'):
            self.transition(previous=self.previous+b' ')

    def test_unknown_inventory_or_changed_context_inventory_refuses(self):
        for rows in [self.new_rows+b'extra\t1\n', self.new_rows.replace(b'owned-other\t1', b'owned-other\t2')]:
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, 'unreviewed_inventory'):
                self.transition(rows=rows)

    def test_known_target_digest_cannot_hide_an_additional_delta(self):
        rows = self.new_rows.replace(b'owned-other\t1', b'owned-other\t2'); digest = self.inventory_hash(rows)
        with mock.patch.object(runtime, 'INVENTORY_BROTLI', digest), self.assertRaisesRegex(ValueError, 'inventory_delta'):
            self.transition(context=dict(self.context, dpkg_inventory_sha256=digest), rows=rows)

    def test_missing_duplicate_wrong_version_and_malformed_packages_refuse(self):
        for rows in [self.new_rows.replace(b'python3-brotli\t1.2.0-3ubuntu0.1\n', b''),
                     self.new_rows+b'python3-brotli\t1.2.0-3ubuntu0.1\n',
                     self.new_rows.replace(b'1.2.0-3ubuntu0.1', b'other'), b'malformed', b'x'*(2*1024**2+1)]:
            with self.subTest(size=len(rows)), self.assertRaises(ValueError):
                self.transition(rows=rows)

    def test_other_platform_fields_still_use_unchanged_real_validator(self):
        for key in ['qemu_binary_sha256', 'host_identity_sha256']:
            context = copy.deepcopy(self.context); context[key] = '0'*64
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'maintenance_binding'):
                self.transition(context=context)
        context = copy.deepcopy(self.context); context['host']['kernel'] = 'other'
        with self.assertRaisesRegex(ValueError, 'maintenance_binding'): self.transition(context=context)

    def test_refresh_requires_root_before_reading_or_writing(self):
        with mock.patch.object(runtime.os, 'geteuid', return_value=1000), \
             mock.patch.object(runtime.subprocess, 'check_output') as commands, self.assertRaises(ValueError):
            runtime.refresh_maintenance()
        commands.assert_not_called()

    def refresh(self, *, reboot=False, audit=b'', changed=False, exists=False, damaged=False):
        writes=[]; saved={}; calls=[]
        def read(fd, name, maximum):
            if name == 'maintenance-'+runtime.MAINTENANCE_PREVIOUS+'.json': return self.previous
            return b'damaged' if damaged else saved[name]
        def exclusive(fd, name, raw):
            saved[name]=raw
            if exists: raise FileExistsError(name)
            writes.append((name,raw))
        fs=SimpleNamespace(execution_lock=nullcontext,read=read,exclusive=exclusive,
                           digest=lambda raw:hashlib.sha256(raw).hexdigest(),
                           make_policy=maintenance_auth.fs.make_policy, IMAGE_SHA256=maintenance_auth.fs.IMAGE_SHA256)
        contexts=[self.context, dict(self.context, dpkg_inventory_sha256='f'*64)] if changed else [self.context]*2
        def output(argv, **kwargs):
            calls.append(argv)
            if argv == ['/usr/bin/dpkg','--audit']: return audit
            self.assertEqual(argv, ['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\n'])
            return self.new_rows
        with mock.patch.object(runtime.os,'geteuid',return_value=0), \
             mock.patch.object(runtime,'snapshot',return_value=GOOD), \
             mock.patch.object(runtime,'network_state',return_value={'same':True}), \
             mock.patch.object(Path,'exists',return_value=reboot), \
             mock.patch.object(runtime.subprocess,'check_output',side_effect=output), \
             mock.patch.object(maintenance_auth,'fs',fs), \
             mock.patch.object(maintenance_auth,'store',side_effect=lambda:nullcontext(1)), \
             mock.patch.object(maintenance_auth,'capture',side_effect=contexts):
            # Only filesystem/host boundaries are substituted. Both the
            # transition and the existing platform/maintenance validators run.
            try: result=runtime.refresh_maintenance()
            except Exception as error: result=error
        return result,writes,calls

    def test_refresh_only_appends_maintenance_and_does_not_enable_execution(self):
        result,writes,calls=self.refresh()
        self.assertEqual(result['result'],'PASS');self.assertEqual(len(writes),1)
        self.assertTrue(writes[0][0].startswith('maintenance-'))
        self.assertFalse(result['i08_installed']);self.assertFalse(result['production_grants_enabled']);self.assertFalse(result['vm_started'])
        self.assertEqual(len(calls),2)

    def test_reboot_package_audit_or_context_race_refuses_without_write(self):
        for kwargs in [{'reboot':True},{'audit':b'incomplete package'},{'changed':True}]:
            result,writes,_=self.refresh(**kwargs)
            with self.subTest(kwargs=kwargs): self.assertIsInstance(result,ValueError);self.assertEqual(writes,[])

    def test_existing_receipt_requires_exact_bytes(self):
        result,writes,_=self.refresh(exists=True);self.assertEqual(result['result'],'PASS');self.assertEqual(writes,[])
        result,_,_=self.refresh(exists=True,damaged=True);self.assertIsInstance(result,ValueError)


class OctoberMaintenance(unittest.TestCase):
    """Exercise the kernel/package transition through the strict real validator."""
    def setUp(self):
        self.old = {b'libbrotli1:amd64': b'1.2.0-3build1',
                    b'python3-brotli': b'1.2.0-3build1', b'owned-other': b'1'}
        self.old.update({k: before for k, (before, _) in runtime.OCT30_PACKAGES.items() if before is not None})
        self.brotli = dict(self.old)
        for key in runtime.BROTLI_PACKAGES: self.brotli[key] = b'1.2.0-3ubuntu0.1'
        self.current = dict(self.brotli)
        for key, (_, after) in runtime.OCT30_PACKAGES.items():
            if after is None: self.current.pop(key)
            else: self.current[key] = after
        self.context = maintenance_context()
        self.context['host']['kernel'] = runtime.OCT30_KERNEL[0]
        self.context['dpkg_inventory_sha256'] = maintenance_auth.digest(self.rows(self.old))
        self.previous = maintenance(self.context)
        self.context = copy.deepcopy(self.context)
        self.context['host']['kernel'] = runtime.OCT30_KERNEL[1]
        self.context['dpkg_inventory_sha256'] = maintenance_auth.digest(self.rows(self.current))
        self.patches = [mock.patch.object(runtime, 'MAINTENANCE_PREVIOUS', maintenance_auth.digest(self.previous)),
            mock.patch.object(runtime, 'INVENTORY_PREVIOUS', maintenance_auth.digest(self.rows(self.old))),
            mock.patch.object(runtime, 'INVENTORY_BROTLI', maintenance_auth.digest(self.rows(self.brotli))),
            mock.patch.object(runtime, 'INVENTORY_OCT30', self.context['dpkg_inventory_sha256'])]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()

    @staticmethod
    def rows(packages): return b'\n'.join(sorted(k+b'\t'+v for k,v in packages.items()))+b'\n'

    def transition(self, packages=None, context=None):
        return runtime.maintenance_transition(self.previous, self.context if context is None else context,
            self.rows(self.current if packages is None else packages))

    def test_stale_binding_refuses_then_only_reviewed_fields_change(self):
        with self.assertRaisesRegex(ValueError, 'maintenance_binding'):
            maintenance_auth.validate_maintenance(self.previous, self.context)
        original = copy.deepcopy(self.context)
        raw = self.transition(); record = maintenance_auth.validate_maintenance(raw, self.context)
        self.assertEqual(self.context, original)
        old = json.loads(self.previous)
        for key in old.keys()-{'kernel', 'dpkg_inventory_sha256', 'review_notes'}:
            self.assertEqual(record[key], old[key])
        self.assertEqual(record['kernel'], runtime.OCT30_KERNEL[1])
        self.assertEqual(record['dpkg_inventory_sha256'], self.context['dpkg_inventory_sha256'])

    def test_pre_reboot_old_kernel_and_unknown_kernel_refuse(self):
        for kernel in [runtime.OCT30_KERNEL[0], '7.0.0-43-generic']:
            context = copy.deepcopy(self.context); context['host']['kernel'] = kernel
            with self.subTest(kernel=kernel), self.assertRaisesRegex(ValueError, 'reviewed_kernel'):
                self.transition(context=context)

    def admitted_digest(self, packages):
        digest = maintenance_auth.digest(self.rows(packages))
        return mock.patch.object(runtime, 'INVENTORY_OCT30', digest), dict(self.context, dpkg_inventory_sha256=digest)

    def test_target_hash_alone_cannot_hide_other_package_change(self):
        for key, value in [(b'owned-other', b'2'), (b'unreviewed-extra', b'1')]:
            packages = dict(self.current); packages[key] = value
            patch, context = self.admitted_digest(packages)
            with patch, self.assertRaisesRegex(ValueError, 'oct30_inventory_delta'):
                self.transition(packages, context)

    def test_each_reviewed_added_removed_and_upgraded_version_is_checked(self):
        for name, (_, after) in runtime.OCT30_PACKAGES.items():
            packages = dict(self.current); packages[name] = b'unreviewed'
            patch, context = self.admitted_digest(packages)
            with self.subTest(name=name, after=after), patch, self.assertRaisesRegex(ValueError, 'package_version'):
                self.transition(packages, context)

    def test_hypervisor_cpu_identity_guest_and_vendor_still_bound(self):
        for key, value in [('qemu_binary_sha256', '0'*64), ('host_identity_sha256', '0'*64),
                           ('cpu_signature', dict(self.context['cpu_signature'], microcode='changed'))]:
            context = copy.deepcopy(self.context); context[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'maintenance_binding'):
                self.transition(context=context)
        previous = json.loads(self.previous); previous['guest_kernel_release'] = 'other'
        raw = maintenance_auth.canonical(previous)
        with mock.patch.object(runtime, 'MAINTENANCE_PREVIOUS', maintenance_auth.digest(raw)), \
             self.assertRaisesRegex(ValueError, 'guest_maintenance_inventory'):
            runtime.maintenance_transition(raw, self.context, self.rows(self.current))

    def test_inventory_change_without_matching_context_refuses(self):
        context = dict(self.context, dpkg_inventory_sha256='0'*64)
        with self.assertRaisesRegex(ValueError, 'unreviewed_inventory'): self.transition(context=context)


if __name__ == '__main__': unittest.main()
