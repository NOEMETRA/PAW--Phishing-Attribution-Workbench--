"""Kernel/protocol substitutions only: never fork, exec, change UID or run a VM."""
from contextlib import ExitStack
import copy
import hashlib
import json
import tempfile
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lab/s14'))
import native_guest as guest


def status():
    return 'Uid:\t65534 65534 65534 65534\nGid:\t65534 65534 65534 65534\nGroups:\nNoNewPrivs:\t1\n'+''.join(
        key+':\t0000000000000000\n' for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'])


def proc_stat(session='123', tty='0', identity='99'):
    fields = ['S', '1', '123', session, tty]+['0']*14+[identity]+['0']*8
    return '123 (trusted controller with spaces) '+' '.join(fields)


class NativeGuest(unittest.TestCase):
    def test_host_refuses_before_input_cgroup_or_spawn(self):
        with mock.patch.object(guest.os, 'geteuid', return_value=1000), mock.patch.object(guest, 'spawn') as spawn, \
             mock.patch.object(guest, 'group') as group, mock.patch.object(guest, 'read_source') as read:
            with self.assertRaisesRegex(ValueError, 'trusted_guest_required'): guest.start()
            spawn.assert_not_called(); group.assert_not_called(); read.assert_not_called()

    def test_fixed_guest_argv_does_not_follow_source_shebang_or_environment(self):
        self.assertEqual(guest.argv_for({'profile': guest.SHELL}), ['/bin/dash', '--', '/opt/paw-input/sample.bin'])
        self.assertEqual(guest.argv_for({'profile': guest.ELF}), ['/opt/paw-input/sample.bin'])
        for profile in ['python', '/bin/bash', 'linux-python-offline-v1']:
            with self.assertRaises(ValueError): guest.argv_for({'profile': profile})

    def test_kernel_status_requires_all_uids_groups_nnp_and_every_capability_zero(self):
        self.assertEqual(guest.validate_status(status())['uid'], 65534)
        changes = [('Uid:\t65534 65534 65534 65534', 'Uid:\t65534 0 65534 65534'),
                   ('Groups:\n', 'Groups:\t27\n'), ('NoNewPrivs:\t1', 'NoNewPrivs:\t0')]
        changes += [(key+':\t0000000000000000', key+':\t0000000000000001') for key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']]
        for before, after in changes:
            with self.subTest(before=before), self.assertRaises(ValueError): guest.validate_status(status().replace(before, after))
        with self.assertRaises(ValueError): guest.validate_status(status()+'Uid:\t65534\n')

    def test_child_enters_writable_work_directory_before_drop_and_fixed_exec(self):
        events=[]
        class ExecReached(BaseException):pass
        def execute(path,argv,env):events.append(('exec',path));raise ExecReached()
        with mock.patch.object(guest.os,'setsid'),mock.patch.object(guest.signal,'signal'), \
             mock.patch.object(guest.os,'dup2'),mock.patch.object(guest.os,'closerange'),mock.patch.object(guest.os,'close'), \
             mock.patch.object(guest.os,'read',return_value=b'G'),mock.patch.object(guest.os,'write',return_value=1), \
             mock.patch.object(guest.os,'chdir',side_effect=lambda p:events.append(('cwd',str(p)))), \
             mock.patch.object(guest,'child_admission',side_effect=lambda:events.append(('drop',65534))), \
             mock.patch.object(guest.os,'execve',side_effect=execute):
            with self.assertRaises(ExecReached):guest._exec_child({'profile':guest.SHELL},108,101,103,105,106)
        self.assertIn(('cwd',str(guest.WORK)),events)
        self.assertLess(events.index(('cwd',str(guest.WORK))),events.index(('drop',65534)))
        self.assertLess(events.index(('drop',65534)),events.index(('exec','/bin/dash')))

    def test_child_admission_drops_bounding_before_uid_and_nnp_after_uid(self):
        events = []
        fake = SimpleNamespace(prctl=lambda *args: events.append(('prctl', args)) or 0)
        with mock.patch.object(guest.ctypes, 'CDLL', return_value=fake), \
             mock.patch.object(Path, 'read_text', return_value='40'), mock.patch.object(Path, 'write_text'), \
             mock.patch.object(guest.resource, 'setrlimit', side_effect=lambda *args: events.append(('rlimit',args))), \
             mock.patch.object(guest.os, 'setgroups', side_effect=lambda v: events.append(('groups',v))), \
             mock.patch.object(guest.os, 'setgid', side_effect=lambda v: events.append(('gid',v))), \
             mock.patch.object(guest.os, 'setuid', side_effect=lambda v: events.append(('uid',v))):
            guest.child_admission()
        self.assertEqual([v[1] for v in events if v[0]=='rlimit'], [(k,(v,v)) for k,v in guest.RLIMITS.items()])
        drops = [v[1] for v in events if v[0]=='prctl' and v[1][0]==24]
        self.assertEqual(drops, [(24,cap,0,0,0) for cap in range(41)])
        uid = events.index(('uid',65534)); self.assertLess(events.index(('prctl',drops[-1])),uid)
        self.assertLess(uid, events.index(('prctl',(38,1,0,0,0))))
        self.assertIn(('groups',[]),events); self.assertIn(('gid',65534),events)

    def test_child_does_not_continue_when_bounding_drop_fails(self):
        with mock.patch.object(guest.ctypes,'CDLL',return_value=SimpleNamespace(prctl=lambda *a:-1)), \
             mock.patch.object(Path,'read_text',return_value='40'), mock.patch.object(Path,'write_text'), \
             mock.patch.object(guest.resource,'setrlimit'), mock.patch.object(guest.os,'setuid') as uid:
            with self.assertRaisesRegex(ValueError,'drop_bounding'):guest.child_admission()
            uid.assert_not_called()

    def boundary_fixture(self, *, session='123', tty='0', changed_limit=False):
        rows = {str(guest.GROUP/name): value for name,value in guest.LIMITS.items()}
        rows.update({str(guest.GROUP/'cgroup.procs'):'123', '/proc/123/status':status(),
                     '/proc/123/stat':proc_stat(session=session,tty=tty), '/proc/123/cgroup':'0::/'+guest.GROUP.name})
        limits = {'Max cpu time':2,'Max file size':4096,'Max core file size':0,'Max open files':32,'Max address space':192*1024**2}
        rows['/proc/123/limits']='Limit Soft Hard Units\n'+''.join(f'{k} {v} {v} units\n' for k,v in limits.items())
        if changed_limit: rows[str(guest.GROUP/'pids.max')]='128'
        return rows

    def test_proc_boundary_observed_before_exec_has_exact_session_limits_and_identity(self):
        rows = self.boundary_fixture()
        with mock.patch.object(Path,'read_text',lambda p,*a,**kw:rows[str(p)]), mock.patch.object(guest.os,'readlink',side_effect=lambda p:'/dev/null' if Path(p).name=='0' else str(guest.WORK)):
            proof = guest.observe_boundary(123)
        self.assertTrue(proof['observed_before_exec']); self.assertEqual(proof['pid_identity'],'99')
        self.assertEqual(proof['session_id'],123); self.assertIsNone(proof['controlling_tty'])
        self.assertEqual(proof['limits'],guest.LIMITS)

    def test_inherited_session_controlling_tty_or_wider_budget_refuses(self):
        for change in [{'session':'1'},{'tty':'1234'},{'changed_limit':True}]:
            rows = self.boundary_fixture(**change)
            with mock.patch.object(Path,'read_text',lambda p,*a,**kw:rows[str(p)]), \
                 mock.patch.object(guest.os,'readlink',side_effect=lambda p:'/dev/null' if Path(p).name=='0' else str(guest.WORK)), self.assertRaises(ValueError):
                guest.observe_boundary(123)

    def test_kernel_working_directory_must_match_the_writable_job_directory(self):
        rows=self.boundary_fixture()
        with mock.patch.object(Path,'read_text',lambda p,*a,**kw:rows[str(p)]), \
             mock.patch.object(guest.os,'readlink',side_effect=lambda p:'/dev/null' if Path(p).name=='0' else '/'), \
             self.assertRaisesRegex(ValueError,'stdin_or_cwd'):
            guest.observe_boundary(123)

    def spawn_fixture(self, refused=False):
        events = []; opened = iter([(100,101),(102,103),(104,105),(106,107)])
        patches = [mock.patch.object(guest.os,'pipe2',side_effect=lambda *a:next(opened)),
                   mock.patch.object(guest.os,'open',return_value=108),mock.patch.object(guest.os,'fork',return_value=123),
                   mock.patch.object(guest.os,'close',side_effect=lambda fd:events.append(('close',fd))),
                   mock.patch.object(guest.os,'read',return_value=b'R'),mock.patch.object(guest.select,'select',return_value=([104],[],[])),
                   mock.patch.object(guest.os,'write',side_effect=lambda fd,raw:events.append(('write',fd,raw)) or len(raw)),
                   mock.patch.object(guest.os,'kill',side_effect=lambda *a:events.append(('kill',a))),
                   mock.patch.object(guest,'_reap',return_value=-signal.SIGKILL)]
        def observe(pid):
            events.append(('observe',pid))
            if refused:raise ValueError('owned fake boundary refusal')
            return {'observed_before_exec':True}
        patches.append(mock.patch.object(guest,'observe_boundary',side_effect=observe))
        with ExitStack() as stack:
            for patch in patches:stack.enter_context(patch)
            if refused:
                with self.assertRaisesRegex(ValueError,'boundary refusal'):guest.spawn({'profile':guest.SHELL})
            else:
                child, streams=guest.spawn({'profile':guest.SHELL})
                self.assertEqual(child['pid'],123);self.assertEqual(streams,[100,102])
        return events

    def test_parent_kernel_observation_precedes_go_and_only_output_fds_transfer(self):
        events=self.spawn_fixture()
        self.assertLess(events.index(('observe',123)),events.index(('write',107,b'G')))
        closed=[v[1] for v in events if v[0]=='close']
        self.assertEqual(set(closed),{101,103,104,105,106,107,108});self.assertEqual(len(closed),7)

    def test_boundary_refusal_prevents_go_kills_child_and_closes_every_parent_fd(self):
        events=self.spawn_fixture(refused=True)
        self.assertFalse(any(v[0]=='write' for v in events));self.assertIn(('kill',(123,signal.SIGKILL)),events)
        self.assertEqual({v[1] for v in events if v[0]=='close'},set(range(100,109)))

    def test_pipe_allocation_failure_closes_already_opened_fds_without_fork(self):
        with mock.patch.object(guest.os,'pipe2',side_effect=[(100,101),OSError('owned descriptor exhaustion')]), \
             mock.patch.object(guest.os,'close') as close, mock.patch.object(guest.os,'fork') as fork:
            with self.assertRaises(OSError):guest.spawn({'profile':guest.SHELL})
            fork.assert_not_called();self.assertEqual({row.args[0] for row in close.call_args_list},{100,101})

    def source_fixture(self, profile, data, *, mode=None, changed=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'sample.bin';source.write_bytes(data)
            source.chmod(mode if mode is not None else 0o444 if profile==guest.SHELL else 0o555)
            config={'schema':'paw-native-seed-v1','profile':profile,'source_sha256':hashlib.sha256(data).hexdigest(),
                    'source_bytes':len(data),'job_sha256':'1'*64,'request_id':'2'*32,'elf_interpreter':None}
            if changed:config.update(changed)
            path=root/'config.json';path.write_text(json.dumps(config))
            original=guest.os.fstat
            def inert_root_stat(fd):
                value=original(fd)
                return SimpleNamespace(**{name:getattr(value,name) for name in ['st_mode','st_nlink','st_size','st_dev','st_ino','st_mtime_ns']},st_uid=0)
            with mock.patch.object(guest,'SOURCE',source),mock.patch.object(guest,'CONFIG',path), \
                 mock.patch.object(guest.os,'fstat',side_effect=inert_root_stat):return guest.read_source()

    def test_exact_full_size_guest_ingress_is_read_only_bytes_without_execution(self):
        shell=b'#'+b'x'*(64*1024-2)+b'\n'
        elf=b'\x7fELF\x02\x01\x01'+bytes(1024**2-7)
        # Full structural ELF admission is separately required on the host.
        # This inert fixture exercises guest byte/hash/cap protection, never a loader.
        for profile,data in [(guest.SHELL,shell),(guest.ELF,elf)]:
            value=self.source_fixture(profile,data);self.assertEqual(value['source_sha256'],hashlib.sha256(data).hexdigest())

    def test_wrong_guest_input_mode_hash_size_profile_or_interpreter_refuses(self):
        cases=[(guest.SHELL,b'printf owned',0o555,None),
               (guest.ELF,b'\x7fELF\x02\x01\x01',0o444,None),
               (guest.SHELL,b'x',None,{'source_sha256':'0'*64}),
               (guest.SHELL,b'x',None,{'source_bytes':True}),
               (guest.SHELL,b'x',None,{'elf_interpreter':'/bin/bash'}),
               (guest.SHELL,b'x\0',None,None),(guest.SHELL,b'\xff',None,None),
               (guest.ELF,b'not an ELF',None,None),(guest.SHELL,b'x'*(64*1024+1),None,None)]
        for profile,data,mode,changed in cases:
            with self.subTest(profile=profile,mode=mode,changed=changed),self.assertRaises(ValueError):
                self.source_fixture(profile,data,mode=mode,changed=changed)

    def test_post_spawn_setup_error_reaps_admitted_child_before_group_cleanup(self):
        events=[];child={'pid':123,'returncode':None,'boundary':{}}
        with mock.patch.object(guest,'guest_only'),mock.patch.object(guest,'USED',False),mock.patch.object(guest,'ACTIVE',None), \
             mock.patch.object(guest,'inspect',return_value={'prior_marker_absent':True}),mock.patch.object(guest,'read_source',return_value={}), \
             mock.patch.object(guest,'group'),mock.patch.object(guest,'clean',side_effect=lambda:events.append('clean')), \
             mock.patch.object(guest,'spawn',return_value=(child,[])), \
             mock.patch.object(guest.selectors,'DefaultSelector',side_effect=OSError('owned selector failure')), \
             mock.patch.object(guest.os,'kill',side_effect=lambda *a:events.append('kill')), \
             mock.patch.object(guest,'_reap',side_effect=lambda *a:events.append('reap') or -9):
            with self.assertRaises(OSError):guest.start()
        self.assertEqual(events,['clean','kill','reap','clean']);self.assertEqual(child['returncode'],-9)

    def test_single_use_or_prior_marker_refuses_before_process_creation(self):
        with mock.patch.object(guest,'guest_only'), mock.patch.object(guest,'USED',True), mock.patch.object(guest,'spawn') as spawn:
            with self.assertRaisesRegex(ValueError,'single_job'):guest.start()
            spawn.assert_not_called()
        with mock.patch.object(guest,'guest_only'), mock.patch.object(guest,'USED',False), \
             mock.patch.object(guest,'inspect',return_value={'prior_marker_absent':False}), mock.patch.object(guest,'group') as group:
            with self.assertRaisesRegex(ValueError,'reset_marker'):guest.start()
            group.assert_not_called()

    def test_oom_status_requires_actual_oom_event_and_zero_remaining_writers(self):
        rows={str(guest.GROUP/'pids.current'):'0',str(guest.GROUP/'memory.events'):'oom 1\noom_kill 1',
              str(guest.GROUP/'memory.peak'):'67108864',str(guest.GROUP/'pids.events'):'max 0',str(guest.GROUP/'pids.peak'):'1'}
        selector=SimpleNamespace(select=lambda **kw:[],close=lambda:None)
        with mock.patch.object(guest,'ACTIVE',{'pid':123,'returncode':-9}), mock.patch.object(guest,'STARTED',0), \
             mock.patch.object(guest,'SELECTOR',selector),mock.patch.object(guest,'STREAMS',[]),mock.patch.object(guest,'BOUNDARY',{'owned':True}), \
             mock.patch.object(guest,'OUTPUT',{'stdout':bytearray(),'stderr':bytearray()}),mock.patch.object(guest.time,'monotonic',return_value=1), \
             mock.patch.object(Path,'read_text',lambda p,*a,**kw:rows[str(p)]),mock.patch.object(Path,'write_text'), \
             mock.patch.object(Path,'lstat',side_effect=FileNotFoundError),mock.patch.object(guest,'clean') as clean:
            value=guest.poll()
        self.assertEqual(value['status'],'memory_budget');self.assertTrue(value['writers_stopped']);clean.assert_called_once()


if __name__=='__main__':unittest.main()
