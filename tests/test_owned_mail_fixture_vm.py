"""Inert selection of the exact private preparation during an owned VM run."""
import unittest
from unittest.mock import Mock, patch
from paw.core import browser_owned_broker as broker, mail_browser_public as public

J, E, R = 'a'*32, 'b'*32, 'c'*40


class MailFixtureVM(unittest.TestCase):
    def test_mail_fixture_uses_exact_private_native_preparation_without_public_mode(self):
        actors = []
        with patch.object(public, 'NetworkPreparation') as prepare, \
             patch.object(broker, 'NetworkPreparation') as legacy:
            value = broker.fixture_preparation(J, E, R, actors, mail_fixture=True)
        prepare.assert_called_once_with(J, E, R, 'owned-browser', actors, protocol=True)
        legacy.assert_not_called()
        self.assertIs(value, prepare.return_value)

    def test_default_and_explicit_legacy_path_still_use_original_preparation(self):
        for kwargs in [{}, {'mail_fixture':False}]:
            with patch.object(public, 'NetworkPreparation') as mail, \
                 patch.object(broker, 'NetworkPreparation') as legacy:
                broker.fixture_preparation(J, E, R, [], **kwargs)
            mail.assert_not_called(); legacy.assert_called_once_with(J, E, R, [])

    def test_only_fixed_boolean_selection_exists(self):
        for value in ['public', 'owned-browser', 1, None, {}, Mock()]:
            with self.subTest(value=value), patch.object(public, 'NetworkPreparation') as prepare, \
                 self.assertRaisesRegex(ValueError, 'fixture_selection'):
                broker.fixture_preparation(J, E, R, [], mail_fixture=value)
            prepare.assert_not_called()

    def test_native_coordinator_partition_and_original_restore_keep_fixed_limits(self):
        with patch.object(broker.subprocess, 'run') as run:
            broker.partition('fixed-parent', mail_fixture=True)
            self.assertEqual(run.call_args.args[0][-3:], ['MemoryMax=192M','TasksMax=24','CPUQuota=35%'])
            broker.partition('fixed-parent', restore=True)
            self.assertEqual(run.call_args.args[0][-3:], ['MemoryMax=512M','TasksMax=64','CPUQuota=100%'])

    def test_legacy_partition_and_restore_are_unchanged(self):
        with patch.object(broker.subprocess, 'run') as run:
            broker.partition('fixed-parent')
            self.assertEqual(run.call_args.args[0][-3:], ['MemoryMax=256M','TasksMax=32','CPUQuota=50%'])

    def test_unprivileged_entry_refuses_before_any_fixture_selection(self):
        with patch.object(broker.kernel, 'owned_validation') as privileged, \
             self.assertRaisesRegex(ValueError, 'immutable_root_only'):
            broker.run_owned(J, R, mail_fixture=True)
        privileged.assert_not_called()


if __name__ == '__main__':
    unittest.main()
