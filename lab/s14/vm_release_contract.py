"""Pure release admission rules; caller-supplied facts are never root authority.

The future privileged adapter must obtain and bind these facts independently.
This module neither fetches proofs, installs polkit, promotes nor executes code.
"""
import json
import re
import time

REPOSITORY = 'NOEMETRA/PAW--Phishing-Attribution-Workbench--'
REVIEWER = 'chatgpt-codex-connector[bot]'
WORKFLOWS = {'.github/workflows/static-integrity.yml': 3,
             '.github/workflows/linux-installed-package.yml': 4}
RECIPES = frozenset({'browser-owned-v1', 'python-owned-v2', 'shell-owned-v1',
                     'elf-owned-v1', 'vm-acceptance-v1'})
MAX_PROOF = 128 * 1024


def require(value, reason):
    if not value: raise ValueError(reason)


def shape(value, fields, reason):
    require(type(value) is dict and set(value) == set(fields), reason)


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{40}', value) is not None


def positive(value): return type(value) is int and value > 0


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PROOF, 'operator_proof_byte_budget')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'operator_duplicate_key'); result[key] = value
        return result
    def constant(value): raise ValueError('operator_nonfinite_json')
    try: value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as error:
        raise ValueError('operator_invalid_json') from error
    pending = [(value, 0)]; count = 0
    while pending:
        item, depth = pending.pop(); count += 1
        require(depth <= 12 and count <= 4096, 'operator_proof_complexity')
        if type(item) is dict: pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list: pending.extend((v, depth + 1) for v in item)
        elif type(item) not in {str, int, bool, type(None)}: raise ValueError('operator_proof_scalar')
    return value


def command(argv):
    require(type(argv) is list and all(type(v) is str for v in argv), 'operator_arguments')
    if argv == ['status']: return 'status', None
    if argv == ['revoke']: return 'revoke', None
    if len(argv) == 2 and argv[0] == 'promote':
        require(re.fullmatch('[1-9][0-9]{0,8}', argv[1]) is not None, 'operator_pull_request_number')
        return 'promote', int(argv[1])
    if len(argv) == 2 and argv[0] == 'run':
        require(argv[1] in RECIPES, 'operator_unknown_recipe'); return 'run', argv[1]
    raise ValueError('operator_unknown_command')


def policy(value, now=None):
    shape(value, {'schema', 'repository', 'owner_uid', 'reviewer_login', 'reviewer_id',
                  'anchor_sha', 'workflows', 'created_at', 'expires_at'}, 'operator_policy_shape')
    now = time.time() if now is None else now
    require(value['schema'] == 'paw-vm-operator-policy-v1' and value['repository'] == REPOSITORY and
            positive(value['owner_uid']) and value['reviewer_login'] == REVIEWER and
            positive(value['reviewer_id']) and sha(value['anchor_sha']), 'operator_policy_identity')
    require(type(value['created_at']) is int and type(value['expires_at']) is int and
            value['created_at'] <= now < value['expires_at'] <= value['created_at'] + 30 * 86400,
            'operator_policy_lease')
    shape(value['workflows'], WORKFLOWS, 'operator_workflow_set')
    for path, expected_count in WORKFLOWS.items():
        item = value['workflows'][path]
        shape(item, {'workflow_id', 'jobs'}, 'operator_workflow_policy')
        require(positive(item['workflow_id']) and type(item['jobs']) is list and
                len(item['jobs']) == expected_count and all(type(v) is str and
                re.fullmatch('[A-Za-z0-9_. ()-]{1,128}', v) for v in item['jobs']) and
                len(set(item['jobs'])) == expected_count, 'operator_required_jobs')
    require(len({v['workflow_id'] for v in value['workflows'].values()}) == 2, 'operator_workflow_ids')
    return value


def release(proof, enrolled, caller_uid, now=None):
    """Validate normalized independent facts; does not authenticate their origin."""
    policy(enrolled, now)
    require(type(caller_uid) is int and caller_uid == enrolled['owner_uid'], 'operator_wrong_caller')
    shape(proof, {'schema', 'repository', 'pull_request', 'head_sha', 'merge_sha',
                  'main_sha', 'anchor_sha', 'anchor_is_ancestor', 'merge_is_main_ancestor',
                  'review', 'ci'}, 'operator_release_shape')
    require(proof['schema'] == 'paw-vm-release-proof-v1' and proof['repository'] == REPOSITORY and
            all(sha(proof[k]) for k in ['head_sha', 'merge_sha', 'main_sha', 'anchor_sha']) and
            proof['anchor_sha'] == enrolled['anchor_sha'] and proof['anchor_is_ancestor'] is True and
            proof['merge_is_main_ancestor'] is True, 'operator_release_history')
    pr = proof['pull_request']; shape(pr, {'number', 'merged', 'base', 'head_repository'}, 'operator_pr_shape')
    require(positive(pr['number']) and pr['number'] <= 999999999 and pr['merged'] is True and
            pr['base'] == 'main' and pr['head_repository'] == REPOSITORY, 'operator_merged_project_pr')
    review = proof['review']
    shape(review, {'receipt_id', 'actor_id', 'actor_login', 'resolved_head_sha',
                   'decision', 'open_threads'}, 'operator_review_shape')
    require(positive(review['receipt_id']) and type(review['actor_id']) is int and
            review['actor_id'] == enrolled['reviewer_id'] and review['actor_login'] == REVIEWER and
            sha(review['resolved_head_sha']) and review['resolved_head_sha'] == proof['head_sha'] and
            review['decision'] == 'no_findings' and type(review['open_threads']) is int and
            review['open_threads'] == 0, 'operator_exact_head_clear_review')
    require(type(proof['ci']) is list and len(proof['ci']) == 4, 'operator_four_required_workflow_runs')
    seen = set(); run_ids = set()
    for run in proof['ci']:
        shape(run, {'run_id', 'run_attempt', 'workflow_path', 'workflow_id', 'head_sha', 'event',
                    'status', 'conclusion', 'jobs'}, 'operator_ci_shape')
        path = run['workflow_path']
        require(type(path) is str and path in WORKFLOWS and type(run['event']) is str and run['event'] in {'pull_request', 'push'},
                'operator_ci_workflow_or_event')
        target = proof['head_sha'] if run['event'] == 'pull_request' else proof['merge_sha']
        key = (path, run['event'])
        require(positive(run['run_id']) and positive(run['run_attempt']) and run['run_id'] not in run_ids and key not in seen and
                type(run['workflow_id']) is int and run['workflow_id'] == enrolled['workflows'][path]['workflow_id'] and
                run['head_sha'] == target and run['status'] == 'completed' and run['conclusion'] == 'success',
                'operator_exact_head_successful_ci')
        require(type(run['jobs']) is list and len(run['jobs']) == WORKFLOWS[path], 'operator_ci_job_count')
        names = []
        for job in run['jobs']:
            shape(job, {'name', 'status', 'conclusion'}, 'operator_job_shape')
            require(type(job['name']) is str and job['status'] == 'completed' and job['conclusion'] == 'success',
                    'operator_completed_successful_job'); names.append(job['name'])
        require(len(set(names)) == len(names) and set(names) == set(enrolled['workflows'][path]['jobs']),
                'operator_required_job_names')
        seen.add(key); run_ids.add(run['run_id'])
    require(seen == {(path, event) for path in WORKFLOWS for event in ['pull_request', 'push']},
            'operator_head_and_main_workflows')
    return {'repository': REPOSITORY, 'head_sha': proof['head_sha'], 'release_sha': proof['merge_sha'],
            'pull_request': pr['number'], 'review_receipt': review['receipt_id'], 'ci_runs': sorted(run_ids)}
