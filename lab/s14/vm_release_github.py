"""Bounded independent GitHub proof acquisition for the enrolled public repo.

An API token is supplied in memory by the caller's credential provider. It is
never persisted, returned in proof data, accepted in a URL or used for mutations.
The privileged dispatcher must instantiate this client itself, not trust JSON
proofs or a caller-selected client/endpoint.
"""
import json
import re
import time
import urllib.error
import urllib.request

from vm_release_contract import REPOSITORY, REVIEWER, WORKFLOWS, policy, release, require, sha, positive, decode, shape

API = 'https://api.github.com'
BASE = '/repos/' + REPOSITORY
QUERY = '''query($number:Int!) {
 repository(owner:"NOEMETRA",name:"PAW--Phishing-Attribution-Workbench--") {
  nameWithOwner isPrivate
  defaultBranchRef { name target { oid } }
  pullRequest(number:$number) {
   number merged baseRefName headRefOid
   headRepository { nameWithOwner }
   mergeCommit { oid parents(first:2) { nodes { oid } } }
   reviewThreads(first:100) { nodes { isResolved } pageInfo { hasNextPage } }
   comments(last:100) { nodes { databaseId body author { login __typename } } }
  }
 }
}'''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise ValueError('github_redirect_refused')


class GitHubClient:
    def __init__(self, token):
        require(type(token) is str and re.fullmatch('[A-Za-z0-9_]{20,256}', token), 'github_api_credential_required')
        self._token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.deadline = time.monotonic() + 120; self.requests = 0; self.bytes = 0

    def request(self, path, payload=None, *, missing=False):
        require(type(path) is str and (path == '/graphql' or path.startswith(BASE+'/')) and
                len(path) <= 4096 and '\r' not in path and '\n' not in path and '#' not in path and
                '/..' not in path, 'github_fixed_endpoint')
        if path == '/graphql':
            require(type(payload) is dict and set(payload) == {'query', 'variables'} and payload['query'] == QUERY and
                    type(payload['variables']) is dict and set(payload['variables']) == {'number'} and
                    positive(payload['variables']['number']) and payload['variables']['number'] <= 999999999,
                    'github_fixed_readonly_query')
        else: require(payload is None, 'github_mutation_refused')
        self.requests += 1
        remaining = self.deadline-time.monotonic()
        require(self.requests <= 32 and remaining > 0, 'github_request_budget')
        data = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        request = urllib.request.Request(API+path, data=data, headers={
            'Authorization': 'Bearer '+self._token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'PAW-fixed-vm-release-verifier',
            **({'Content-Type': 'application/json'} if data is not None else {})})
        try:
            with self._opener.open(request, timeout=min(15, remaining)) as response:
                require(response.geturl() == API+path, 'github_response_endpoint_changed')
                raw = response.read(1024**2+1)
        except urllib.error.HTTPError as error:
            code = error.code; error.close()
            if missing and code == 404: return None
            raise ValueError('github_http_status:'+str(code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ValueError('github_transport_unavailable') from None
        self.bytes += len(raw)
        require(len(raw) <= 1024**2 and self.bytes <= 8*1024**2, 'github_response_byte_budget')
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, 'github_duplicate_key'); result[key] = value
            return result
        def constant(value): raise ValueError('github_nonfinite_json')
        try: result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        except (UnicodeError, RecursionError, json.JSONDecodeError): raise ValueError('github_invalid_json') from None
        require(type(result) is dict, 'github_response_object'); return result

    def get(self, path, *, missing=False): return self.request(path, missing=missing)
    def query(self, number): return self.request('/graphql', {'query': QUERY, 'variables': {'number': number}})


def ancestry(client, older, newer):
    require(sha(older) and sha(newer), 'github_ancestry_commits')
    value = client.get(BASE+'/compare/'+older+'...'+newer)
    require(value.get('status') in {'ahead', 'identical'} and
            value.get('merge_base_commit', {}).get('sha') == older, 'github_required_ancestry')


def review_state(body, head):
    """Automatic promotion requires full structured commit identity, not prose."""
    require(type(body) is str and len(body) <= 16384, 'github_review_state_budget')
    if not body.startswith('<!-- codex-pull-request-review-summary -->'): return None
    markers = re.findall(r'<!-- codex-review-state:v1 (\{[^\n]*\}) -->', body)
    require(len(markers) == 1, 'github_review_state_marker')
    value = decode(markers[0].encode()); shape(value, {'code_review', 'security_review'}, 'github_review_state_shape')
    code = value['code_review']; security = value['security_review']
    fields = {'commit_sha', 'has_any_findings', 'has_unresolved_findings', 'status'}
    shape(code, fields, 'github_code_review_shape'); shape(security, fields, 'github_security_review_shape')
    if code['commit_sha'] != head: return None
    require(sha(code['commit_sha']) and code['status'] == 'completed' and
            code['has_any_findings'] is False and code['has_unresolved_findings'] is False,
            'github_current_head_clear_code_review')
    if not all(v is None for v in security.values()):
        require(security['commit_sha'] == head and security['status'] == 'completed' and
                security['has_any_findings'] is False and security['has_unresolved_findings'] is False,
                'github_pending_or_failed_security_review')
    return code


def ci_run(client, path, enrolled, head, event):
    workflow = enrolled['workflows'][path]['workflow_id']
    value = client.get(BASE+f'/actions/workflows/{workflow}/runs?head_sha={head}&event={event}&per_page=20')
    runs = value.get('workflow_runs')
    require(type(runs) is list and 1 <= len(runs) <= 20, 'github_workflow_runs')
    # A newer queued/failed run cannot be hidden behind an older green run.
    require(all(type(v) is dict and positive(v.get('id')) for v in runs), 'github_run_identifiers')
    run = max(runs, key=lambda v: v['id'])
    require(run.get('head_sha') == head and run.get('event') == event and
            type(run.get('workflow_id')) is int and run['workflow_id'] == workflow and
            run.get('path') == path and run.get('status') == 'completed' and
            run.get('conclusion') == 'success', 'github_latest_exact_head_green_run')
    jobs = client.get(BASE+f"/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")
    rows = jobs.get('jobs')
    require(type(jobs.get('total_count')) is int and type(rows) is list and
            len(rows) == jobs['total_count'] == WORKFLOWS[path], 'github_complete_required_jobs')
    return {'run_id': run['id'], 'workflow_path': path, 'workflow_id': workflow, 'head_sha': head,
            'event': event, 'status': run['status'], 'conclusion': run['conclusion'],
            'jobs': [{k: row.get(k) for k in ['name', 'status', 'conclusion']} for row in rows]}


def collect(client, number, enrolled):
    """The installed caller must supply its own client and root-enrolled policy."""
    policy(enrolled); require(positive(number) and number <= 999999999, 'github_pr_number')
    response = client.query(number); require(not response.get('errors'), 'github_graphql_errors')
    repo = response.get('data', {}).get('repository')
    require(type(repo) is dict and repo.get('nameWithOwner') == REPOSITORY and repo.get('isPrivate') is False,
            'github_enrolled_public_repository')
    pr = repo.get('pullRequest'); main = repo.get('defaultBranchRef')
    require(type(pr) is dict and pr.get('number') == number and pr.get('merged') is True and
            pr.get('baseRefName') == 'main' and pr.get('headRepository', {}).get('nameWithOwner') == REPOSITORY and
            type(main) is dict and main.get('name') == 'main', 'github_merged_enrolled_pr')
    head = pr.get('headRefOid'); merge = pr.get('mergeCommit', {}).get('oid'); main_sha = main.get('target', {}).get('oid')
    require(all(sha(v) for v in [head, merge, main_sha]), 'github_full_commit_identity')
    parents = pr['mergeCommit'].get('parents', {}).get('nodes')
    require(type(parents) is list and len(parents) == 2 and
            all(type(v) is dict and sha(v.get('oid')) for v in parents) and
            head in {v['oid'] for v in parents}, 'github_merge_parent_binding')
    threads = pr.get('reviewThreads', {})
    require(threads.get('pageInfo', {}).get('hasNextPage') is False and type(threads.get('nodes')) is list and
            len(threads['nodes']) <= 100 and all(v.get('isResolved') is True for v in threads['nodes']),
            'github_all_review_threads_resolved')
    comments = pr.get('comments', {}).get('nodes'); require(type(comments) is list and len(comments) <= 100, 'github_review_receipts')
    candidates = []
    for comment in comments:
        if type(comment) is not dict: continue
        actor = comment.get('author')
        if not (type(actor) is dict and actor.get('__typename') == 'Bot' and
                actor.get('login') in {REVIEWER, REVIEWER.removesuffix('[bot]')}): continue
        body = comment.get('body'); ident = comment.get('databaseId')
        if not (type(body) is str and len(body) <= 16384 and positive(ident)): continue
        state = review_state(body, head)
        if state is not None: candidates.append((ident, body))
    require(candidates, 'github_completed_current_head_review_required')
    ident, body = max(candidates)
    receipt = client.get(BASE+f'/issues/comments/{ident}')
    require(receipt.get('id') == ident and receipt.get('body') == body and
            receipt.get('issue_url') == 'https://api.github.com'+BASE+f'/issues/{number}' and
            receipt.get('user', {}).get('id') == enrolled['reviewer_id'] and
            receipt.get('user', {}).get('login') == REVIEWER, 'github_review_actor_and_pr')
    require(review_state(receipt['body'], head) is not None, 'github_authenticated_full_head_review')
    ancestry(client, enrolled['anchor_sha'], merge); ancestry(client, merge, main_sha)
    proof = {'schema': 'paw-vm-release-proof-v1', 'repository': REPOSITORY,
        'pull_request': {'number': number, 'merged': True, 'base': 'main', 'head_repository': REPOSITORY},
        'head_sha': head, 'merge_sha': merge, 'main_sha': main_sha, 'anchor_sha': enrolled['anchor_sha'],
        'anchor_is_ancestor': True, 'merge_is_main_ancestor': True,
        'review': {'receipt_id': ident, 'actor_id': enrolled['reviewer_id'], 'actor_login': REVIEWER,
                   'resolved_head_sha': head, 'decision': 'no_findings', 'open_threads': 0},
        'ci': [ci_run(client, path, enrolled, sha_value, event) for event, sha_value in
               [('pull_request', head), ('push', merge)] for path in WORKFLOWS]}
    # Reject a changed PR/main observation instead of mixing two releases.
    fresh = client.query(number)
    require(not fresh.get('errors'), 'github_final_graphql_errors')
    final = fresh.get('data', {}).get('repository', {})
    require(final.get('pullRequest') == pr and final.get('defaultBranchRef') == main and
            final.get('nameWithOwner') == REPOSITORY, 'github_proof_changed_during_collection')
    release(proof, enrolled, enrolled['owner_uid']); return proof
