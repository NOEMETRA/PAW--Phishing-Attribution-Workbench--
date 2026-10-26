"""Inert deployment-boundary tests; no root, network, password or VM."""
import copy
import json
import unittest

import vm_release_contract as contract


def fixture():
    workflows = {path: {'workflow_id': index, 'jobs': [f'job-{index}-{n}' for n in range(count)]}
                 for index, (path, count) in enumerate(contract.WORKFLOWS.items(), 1)}
    policy = {'schema': 'paw-vm-operator-policy-v1', 'repository': contract.REPOSITORY,
              'owner_uid': 1000, 'reviewer_login': contract.REVIEWER, 'reviewer_id': 123,
              'anchor_sha': 'a'*40, 'workflows': workflows, 'created_at': 100, 'expires_at': 1000}
    proof = {'schema': 'paw-vm-release-proof-v1', 'repository': contract.REPOSITORY,
             'pull_request': {'number': 111, 'merged': True, 'base': 'main', 'head_repository': contract.REPOSITORY},
             'head_sha': 'b'*40, 'merge_sha': 'c'*40, 'main_sha': 'd'*40, 'anchor_sha': 'a'*40,
             'anchor_is_ancestor': True, 'merge_is_main_ancestor': True,
             'review': {'receipt_id': 12, 'actor_id': 123, 'actor_login': contract.REVIEWER,
                        'resolved_head_sha': 'b'*40, 'decision': 'no_findings', 'open_threads': 0}, 'ci': []}
    for event, sha in [('pull_request', proof['head_sha']), ('push', proof['merge_sha'])]:
        for path, value in workflows.items():
            proof['ci'].append({'run_id': len(proof['ci'])+1, 'run_attempt': 1, 'workflow_path': path,
                'workflow_id': value['workflow_id'], 'event': event, 'head_sha': sha,
                'status': 'completed', 'conclusion': 'success',
                'jobs': [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in value['jobs']]})
    return policy, proof


class ReleaseContract(unittest.TestCase):
    def setUp(self): self.policy, self.proof = fixture()

    def admit(self, proof=None, policy=None, uid=1000, now=200):
        return contract.release(self.proof if proof is None else proof,
                                self.policy if policy is None else policy, uid, now)

    def test_exact_head_and_merge_required_runs_admit_only_normalized_identity(self):
        result = self.admit()
        self.assertEqual(result, {'repository': contract.REPOSITORY, 'head_sha': 'b'*40,
            'release_sha': 'c'*40, 'pull_request': 111, 'review_receipt': 12, 'ci_runs': [1, 2, 3, 4]})

    def test_unmerged_foreign_fork_other_branch_and_truthy_flags_refuse(self):
        for key, value in [('merged', False), ('merged', 1), ('base', 'feature'),
                           ('head_repository', 'foreign/project'), ('number', True)]:
            changed = copy.deepcopy(self.proof); changed['pull_request'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.admit(changed)

    def test_full_resolved_review_head_is_mandatory(self):
        for value in ['b'*10, 'e'*40, 'b'*39, True, None]:
            changed = copy.deepcopy(self.proof); changed['review']['resolved_head_sha'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.admit(changed)

    def test_spoofed_actor_pending_review_or_open_thread_refuses(self):
        for key, value in [('actor_id', 456), ('actor_id', True), ('actor_login', 'user'),
                           ('decision', 'queued'), ('open_threads', 1), ('open_threads', False)]:
            changed = copy.deepcopy(self.proof); changed['review'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.admit(changed)

    def test_ancestry_flags_and_anchor_cannot_be_replaced_by_other_commits(self):
        for key, value in [('anchor_is_ancestor', False), ('anchor_is_ancestor', 1),
                           ('merge_is_main_ancestor', False), ('anchor_sha', 'e'*40),
                           ('main_sha', '../path')]:
            changed = copy.deepcopy(self.proof); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.admit(changed)

    def test_ci_from_previous_head_or_other_workflow_refuses(self):
        for key, value in [('head_sha', 'e'*40), ('workflow_id', 999), ('workflow_id', True),
                           ('workflow_path', 'user/workflow.yml'), ('event', 'pull_request_target'), ('event', []),
                           ('run_attempt', True), ('run_attempt', 0)]:
            changed = copy.deepcopy(self.proof); changed['ci'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.admit(changed)

    def test_pending_failed_or_skipped_run_and_jobs_refuse(self):
        for where in ['run', 'job']:
            for key, value in [('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'skipped')]:
                changed = copy.deepcopy(self.proof); target = changed['ci'][0]
                if where == 'job': target = target['jobs'][0]
                target[key] = value
                with self.subTest(where=where, key=key, value=value), self.assertRaises(ValueError): self.admit(changed)

    def test_duplicate_missing_or_replaced_required_jobs_refuse(self):
        for mutation in ['duplicate', 'missing', 'replace']:
            changed = copy.deepcopy(self.proof); jobs = changed['ci'][0]['jobs']
            if mutation == 'duplicate': jobs[1] = dict(jobs[0])
            elif mutation == 'missing': jobs.pop()
            else: jobs[0]['name'] = 'unrelated-green-job'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.admit(changed)

    def test_run_reuse_or_missing_main_workflow_refuses(self):
        for mutation in ['duplicate_id', 'duplicate_workflow', 'missing', 'wrong_merge']:
            changed = copy.deepcopy(self.proof)
            if mutation == 'duplicate_id': changed['ci'][1]['run_id'] = changed['ci'][0]['run_id']
            elif mutation == 'duplicate_workflow': changed['ci'][1] = copy.deepcopy(changed['ci'][0]); changed['ci'][1]['run_id'] = 10
            elif mutation == 'missing': changed['ci'].pop()
            else: changed['ci'][2]['head_sha'] = changed['head_sha']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.admit(changed)

    def test_unenrolled_user_and_boolean_identity_refuse(self):
        for value in [0, 1001, True, '1000']:
            with self.subTest(value=value), self.assertRaises(ValueError): self.admit(uid=value)

    def test_policy_expiry_and_maximum_lease_are_enforced(self):
        for now in [99, 1000, 1001]:
            with self.subTest(now=now), self.assertRaises(ValueError): self.admit(now=now)
        changed = copy.deepcopy(self.policy); changed['expires_at'] = 100 + 31*86400
        with self.assertRaises(ValueError): self.admit(policy=changed)

    def test_policy_cannot_enroll_root_or_expand_job_set(self):
        for key, value in [('owner_uid', 0), ('owner_uid', True), ('reviewer_login', 'user')]:
            changed = copy.deepcopy(self.policy); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.admit(policy=changed)
        changed = copy.deepcopy(self.policy); next(iter(changed['workflows'].values()))['jobs'].append('extra')
        with self.assertRaises(ValueError): self.admit(policy=changed)

    def test_unknown_fields_are_not_forwarded_to_privileged_execution(self):
        for where in ['root', 'review', 'ci', 'job']:
            changed = copy.deepcopy(self.proof)
            target = {'root': changed, 'review': changed['review'], 'ci': changed['ci'][0], 'job': changed['ci'][0]['jobs'][0]}[where]
            target['command'] = '/bin/sh'
            with self.subTest(where=where), self.assertRaises(ValueError): self.admit(changed)

    def test_command_arguments_have_no_general_execution_or_input_path(self):
        self.assertEqual(contract.command(['status']), ('status', None))
        self.assertEqual(contract.command(['revoke']), ('revoke', None))
        self.assertEqual(contract.command(['promote', '111']), ('promote', 111))
        for name in contract.RECIPES: self.assertEqual(contract.command(['run', name]), ('run', name))
        for value in [[], ['sh'], ['run', '/tmp/user.py'], ['run', 'browser-owned-v1', '--url', 'x'],
                      ['promote', '+111'], ['promote', '0'], ['promote', '111;id'], ['status', '--path', '/etc/shadow'],
                      ['run', 'real-sample'], ['run', 'browser-owned-v1\0'], [True]]:
            with self.subTest(value=value), self.assertRaises(ValueError): contract.command(value)

    def test_proof_json_refuses_duplicate_nonfinite_deep_or_unbounded_input(self):
        self.assertEqual(contract.decode(json.dumps(self.proof).encode()), self.proof)
        for value in [b'{"a":1,"a":2}', b'{"n":NaN}', b'{"n":1e999}', b'\xff',
                      b'['*20+b'0'+b']'*20, b' '* (contract.MAX_PROOF+1), b'']:
            with self.subTest(prefix=value[:30]), self.assertRaises(ValueError): contract.decode(value)


if __name__ == '__main__': unittest.main()
