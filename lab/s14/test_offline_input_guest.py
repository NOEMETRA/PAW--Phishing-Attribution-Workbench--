"""Deterministic reset/start ordering without root, VM or sample execution."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import offline_input_guest as guest


class ResetAdmission(unittest.TestCase):
    def test_child_marker_cannot_change_pre_execution_reset_observation(self):
        source = b'owned inert source'
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            def spawn(*_):
                (work / 'previous-job-marker').write_text('created by fake child before returning')
                pipe = SimpleNamespace(fileno=lambda: 99)
                return SimpleNamespace(pid=123, stdout=pipe, stderr=pipe)
            config = {'source_sha256': hashlib.sha256(source).hexdigest(), 'job_sha256': '0' * 64}
            with mock.patch.object(guest, 'WORK', work), mock.patch.object(guest, 'USED', False), \
                 mock.patch.object(guest, 'ACTIVE', None), mock.patch.object(guest, 'STARTED', None), \
                 mock.patch.object(guest, 'clean'), mock.patch.object(guest, 'group'), \
                 mock.patch.object(guest, 'isolated_process', side_effect=spawn), \
                 mock.patch.object(guest.os, 'set_blocking'), \
                 mock.patch.object(guest, 'SELECTOR', SimpleNamespace(register=lambda *a: None)), \
                 mock.patch.object(Path, 'read_bytes', return_value=source), \
                 mock.patch.object(Path, 'read_text', return_value=json.dumps(config)):
                result = guest.start()
            self.assertTrue((work / 'previous-job-marker').exists())
            self.assertIs(result['prior_marker_absent'], True)

    def test_stale_marker_refuses_before_spawning_or_creating_job_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory); (work / 'previous-job-marker').write_text('prior job')
            with mock.patch.object(guest, 'WORK', work), mock.patch.object(guest, 'USED', False), \
                 mock.patch.object(guest, 'group') as group, \
                 mock.patch.object(guest, 'isolated_process') as spawn:
                with self.assertRaisesRegex(ValueError, 'before_execution'): guest.start()
                group.assert_not_called(); spawn.assert_not_called()


if __name__ == '__main__': unittest.main()
