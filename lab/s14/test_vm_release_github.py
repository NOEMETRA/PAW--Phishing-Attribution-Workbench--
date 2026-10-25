"""Independent proof acquisition fixtures; no credentials, network or root."""
import copy
import json
import time
import unittest
from unittest.mock import Mock

import vm_release_github as remote
import vm_release_contract as contract
from test_vm_release_contract import fixture


class FakeGitHub:
    def __init__(self, enrolled, proof):
        self.policy = enrolled; self.proof = proof; self.queries = 0; self.options = set()
        self.state = {'code_review': {'commit_sha': proof['head_sha'], 'status': 'completed',
                      'has_any_findings': False, 'has_unresolved_findings': False},
                      'security_review': dict.fromkeys(['commit_sha', 'status', 'has_any_findings', 'has_unresolved_findings'])}
        self.body = '<!-- codex-pull-request-review-summary -->\n<!-- codex-review-state:v1 '+json.dumps(self.state)+' -->'
        self.repo = {'nameWithOwner': contract.REPOSITORY, 'isPrivate': False,
            'defaultBranchRef': {'name': 'main', 'target': {'oid': proof['main_sha']}},
            'pullRequest': {'number': 111, 'merged': True, 'baseRefName': 'main', 'headRefOid': proof['head_sha'],
                'headRepository': {'nameWithOwner': contract.REPOSITORY},
                'mergeCommit': {'oid': proof['merge_sha'], 'parents': {'nodes': [{'oid': proof['anchor_sha']}, {'oid': proof['head_sha']}]}},
                'reviewThreads': {'nodes': [{'isResolved': True}], 'pageInfo': {'hasNextPage': False}},
                'comments': {'nodes': [{'databaseId': 12, 'body': self.body, 'author': {'login': contract.REVIEWER.removesuffix('[bot]'), '__typename': 'Bot'}}]}}}

    def query(self, number):
        self.queries += 1; repo = copy.deepcopy(self.repo)
        if self.queries == 2 and 'changed' in self.options: repo['pullRequest']['headRefOid'] = 'e'*40
        if self.queries == 2 and 'ci_changed' in self.options: self.options.add('queued')
        if self.queries == 2 and 'ci_rerun' in self.options: self.options.add('rerun')
        return {'data': {'repository': repo}}

    def get(self, path, *, missing=False):
        if '/issues/comments/' in path:
            return {'id': 12, 'body': self.body, 'issue_url': 'https://api.github.com'+remote.BASE+'/issues/111',
                    'user': {'id': 999 if 'actor' in self.options else self.policy['reviewer_id'], 'login': contract.REVIEWER}}
        if '/compare/' in path:
            older = path.split('/compare/')[1].split('...')[0]
            return {'status': 'diverged' if 'history' in self.options else 'ahead', 'merge_base_commit': {'sha': older}}
        if '/actions/workflows/' in path:
            workflow = int(path.split('/workflows/')[1].split('/')[0])
            event = 'push' if 'event=push' in path else 'pull_request'
            run, = [v for v in self.proof['ci'] if v['workflow_id'] == workflow and v['event'] == event]
            row = copy.deepcopy(run); row.update(id=row['run_id'], path=row['workflow_path'])
            row['run_attempt'] = 2 if 'rerun' in self.options else 1
            if 'queued' in self.options: row['status'] = 'in_progress'
            if 'stale' in self.options: row['head_sha'] = 'e'*40
            return {'workflow_runs': [row]}
        if '/actions/runs/' in path:
            rid = int(path.split('/runs/')[1].split('/')[0]); run, = [v for v in self.proof['ci'] if v['run_id'] == rid]
            jobs = copy.deepcopy(run['jobs'])
            if 'skipped' in self.options: jobs[0]['conclusion'] = 'skipped'
            return {'total_count': len(jobs), 'jobs': jobs}
        raise AssertionError('Unanticipated endpoint '+path)


class GitHubProof(unittest.TestCase):
    def setUp(self):
        self.policy, self.proof = fixture(); now = int(time.time())
        self.policy.update(created_at=now-1, expires_at=now+3600)
        self.client = FakeGitHub(self.policy, self.proof)

    def test_independent_collection_binds_review_threads_full_head_and_four_ci_runs(self):
        self.assertEqual(remote.collect(self.client, 111, self.policy), self.proof)
        self.assertEqual(self.client.queries, 2)

    def test_other_actor_ref_shadow_resolution_history_or_latest_ci_refuse(self):
        for option in ['actor', 'history', 'queued', 'stale', 'skipped', 'changed']:
            self.client = FakeGitHub(self.policy, self.proof); self.client.options.add(option)
            with self.subTest(option=option), self.assertRaises(ValueError): remote.collect(self.client, 111, self.policy)

    def test_unresolved_or_unenumerated_threads_do_not_become_clear(self):
        for mutation in ['open', 'paginated']:
            client = FakeGitHub(self.policy, self.proof); threads = client.repo['pullRequest']['reviewThreads']
            if mutation == 'open': threads['nodes'][0]['isResolved'] = False
            else: threads['pageInfo']['hasNextPage'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): remote.collect(client, 111, self.policy)

    def test_ci_requeued_or_rerun_during_final_graphql_observation_refuses(self):
        for mutation in ['ci_changed', 'ci_rerun']:
            client = FakeGitHub(self.policy, self.proof); client.options.add(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): remote.collect(client, 111, self.policy)

    def test_missing_foreign_or_unfinished_receipt_refuses(self):
        for mutation in ['missing', 'user', 'queued', 'other_head']:
            client = FakeGitHub(self.policy, self.proof); comments = client.repo['pullRequest']['comments']['nodes']
            if mutation == 'missing': comments.clear()
            elif mutation == 'user': comments[0]['author']['login'] = 'untrusted-user'
            elif mutation == 'queued': comments[0]['body'] = 'Review is running'
            else: comments[0]['body'] = client.body.replace('b'*40, 'e'*40)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): remote.collect(client, 111, self.policy)

    def test_private_fork_unmerged_or_non_parent_merge_refuses(self):
        for mutation in ['private', 'fork', 'unmerged', 'parent']:
            client = FakeGitHub(self.policy, self.proof); pr = client.repo['pullRequest']
            if mutation == 'private': client.repo['isPrivate'] = True
            elif mutation == 'fork': pr['headRepository']['nameWithOwner'] = 'other/repo'
            elif mutation == 'unmerged': pr['merged'] = False
            else: pr['mergeCommit']['parents']['nodes'] = [{'oid': 'e'*40}, {'oid': 'f'*40}]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): remote.collect(client, 111, self.policy)

    def test_client_cannot_send_mutations_arbitrary_query_or_cross_host_credentials(self):
        client = remote.GitHubClient('fixture_token_not_a_real_secret_12345')
        client._opener = Mock()
        calls = [(remote.BASE+'/issues', {'title': 'mutation'}), ('/graphql', {'query': 'mutation {}'}),
                 ('https://other.invalid/', None), (remote.BASE+'/../other', None),
                 ('/graphql', {'query': remote.QUERY, 'variables': {'number': True}})]
        for path, payload in calls:
            with self.subTest(path=path), self.assertRaises(ValueError): client.request(path, payload)
        client._opener.open.assert_not_called()

    def test_credential_shape_and_redirects_fail_without_disclosing_credential(self):
        for value in ['', 'token\nheader', 'https://token.invalid/', True]:
            with self.subTest(value=value), self.assertRaises(ValueError): remote.GitHubClient(value)
        with self.assertRaises(ValueError): remote.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid/')

    def test_structured_state_has_full_sha_and_pending_security_is_not_clear(self):
        head = self.proof['head_sha']
        for mutation in ['short', 'pending', 'findings', 'truthy', 'security']:
            state = copy.deepcopy(self.client.state)
            if mutation == 'short': state['code_review']['commit_sha'] = head[:10]
            elif mutation == 'pending': state['code_review']['status'] = 'running'
            elif mutation == 'findings': state['code_review']['has_any_findings'] = True
            elif mutation == 'truthy': state['code_review']['has_unresolved_findings'] = 0
            else: state['security_review']['status'] = 'running'
            body = '<!-- codex-pull-request-review-summary -->\n<!-- codex-review-state:v1 '+json.dumps(state)+' -->'
            with self.subTest(mutation=mutation):
                if mutation == 'short': self.assertIsNone(remote.review_state(body, head))
                else:
                    with self.assertRaises(ValueError): remote.review_state(body, head)
        self.assertIsNone(remote.review_state('**Reviewed commit:** `'+head[:10]+'`', head))


if __name__ == '__main__': unittest.main()
