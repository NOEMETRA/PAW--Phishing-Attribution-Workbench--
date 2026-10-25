"""Temporary role fixtures only; never installs real readiness or starts a VM."""
import contextlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_browser_contract as support

auth = support.auth


def readiness(context):
    return auth.canonical({'schema':'paw-s14-browser-i08-readiness-v1',
        'decision':'ready-for-explicit-single-hash-offline-html-grants',
        'context_sha256':auth.digest(auth.canonical(context)), 'reviewed_head':'a'*40,
        'review_url':'https://github.com/NOEMETRA/PAW--Phishing-Attribution-Workbench--/pull/110#issuecomment-1',
        'ci_runs':[1,2], 'ci_successful_jobs':7, 'created_at':100, 'expires_at':1000})


class Readiness(unittest.TestCase):
    def test_analysis_needs_installed_current_receipt_and_exactly_one_source(self):
        context = support.Authority().context(); ready = readiness(context); value = support.frame(now=100)
        raw = auth.canonical(value); sha = value['source']['sha256']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            @contextlib.contextmanager
            def opened():
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:yield fd
                finally:os.close(fd)
            with patch.object(auth,'store',opened), patch.object(auth.fs,'OWNER_UID',os.getuid()), \
                    patch.object(auth.os,'geteuid',return_value=0), patch.object(auth.platform,'validate_context'), \
                    patch.object(auth,'capture',return_value=context), patch.object(auth.time,'time',return_value=102):
                with self.assertRaises(ValueError):auth.make_policy(context,[sha],mode='sample-analysis')
                with self.assertRaises(ValueError):auth.make_policy(context,[sha,'e'*64],mode='sample-analysis',readiness_raw=ready)
                policy=auth.make_policy(context,[sha],mode='sample-analysis',readiness_raw=ready)
                with self.assertRaises(FileNotFoundError):auth.install_policy(policy,context)
                self.assertFalse(list(root.glob('policy-*')))
                auth.install_readiness(ready,context);auth.install_policy(policy,context)
                grant=auth.issue(raw,policy,context);self.assertEqual(grant['execution_purpose'],'sample-analysis')
                ledger,_,_,_,source=auth.consume(raw,policy,context)
                self.assertEqual(source,b'<title>owned</title>');auth.confirm_consumed(ledger)
                with self.assertRaises(FileExistsError):auth.consume(raw,policy,context)

    def test_stale_or_cross_context_review_ci_receipts_refuse(self):
        context=support.Authority().context();valid=json.loads(readiness(context))
        for key,changed in [('context_sha256','0'*64),('reviewed_head','bad'),('review_url','https://other.invalid/'),
                            ('ci_successful_jobs',6),('ci_runs',[1,1]),('expires_at',101)]:
            value=dict(valid);value[key]=changed
            with self.subTest(key=key),self.assertRaises(ValueError):auth.validate_readiness(auth.canonical(value),context,now=102)


if __name__=='__main__':unittest.main()
