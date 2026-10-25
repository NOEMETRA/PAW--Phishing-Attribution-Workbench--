"""Inert renderer startup/reuse regressions; never launches Chrome or a guest."""
import unittest
from browser_sandbox import RendererWitness, renderer_command


def sample(witness, identity='100:200', *, seccomp=2, nnp=1, namespace=True, uids=None, command=b'chrome\0--type=renderer\0'):
    witness.add(identity, command, seccomp=seccomp, nnp=nnp, pid_namespace=namespace,
                uids=[65534]*4 if uids is None else uids)


class RendererObservation(unittest.TestCase):
    def test_packed_linux_process_titles_keep_exact_quoted_argument_boundaries(self):
        packed=b'/opt/google/chrome/chrome --type=renderer --renderer-client-id=7\0\0'
        w=RendererWitness();sample(w,command=packed);self.assertTrue(all(w.flags().values()))
        self.assertTrue(w.diagnostics()['type_markers'][0]['matched'])
        for command in [b'chrome --type=renderer-spare\0',b'chrome --annotation="owned --type=renderer text"\0']:
            with self.subTest(command=command):self.assertFalse(renderer_command(command))
        with self.assertRaises(ValueError):renderer_command(b'chrome --type=renderer "unterminated\0')
        with self.assertRaises(ValueError):renderer_command(b'x'*32769)

    def test_startup_zero_then_filter_two_is_retained_and_requires_final_witness(self):
        w=RendererWitness();sample(w,seccomp=0,namespace=False)
        self.assertFalse(w.flags()['renderer_seccomp'])
        sample(w);self.assertTrue(all(w.flags().values()));self.assertEqual(w.details()[0]['modes'],[0,2])

    def test_every_identity_requires_filter_and_pid_reuse_cannot_borrow_an_old_witness(self):
        w=RendererWitness();sample(w);sample(w,'100:201',seccomp=0)
        self.assertFalse(w.flags()['renderer_seccomp']);sample(w,'100:201');self.assertTrue(all(w.flags().values()))
        sample(w,'101:202',seccomp=0);self.assertFalse(w.flags()['renderer_seccomp'])

    def test_filter_regression_or_unsafe_filtered_snapshot_never_recovers(self):
        for fault in ['regress','nnp','uid','namespace']:
            w=RendererWitness();sample(w)
            if fault=='regress':sample(w,seccomp=0)
            elif fault=='nnp':sample(w,nnp=0)
            elif fault=='uid':sample(w,uids=[0,65534,65534,65534])
            else:sample(w,namespace=False)
            sample(w)
            with self.subTest(fault=fault):self.assertFalse(all(w.flags().values()))

    def test_exact_renderer_argument_is_required(self):
        w=RendererWitness();sample(w,command=b'chrome\0--type=renderer-spare\0')
        self.assertFalse(w.flags()['renderer_seen']);sample(w,command=b'chrome\0--annotation=--type=renderer\0')
        self.assertFalse(w.flags()['renderer_seen']);sample(w);self.assertTrue(all(w.flags().values()))

    def test_identity_tracking_is_bounded(self):
        w=RendererWitness()
        for i in range(64):sample(w,str(i)+':owned')
        with self.assertRaisesRegex(ValueError,'renderer_(identity|marker)_budget'):sample(w,'65:owned')


if __name__=='__main__':unittest.main()
