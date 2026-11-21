"""Evaluate saved PAW decisions against a separately adjudicated holdout manifest."""
import argparse
from collections import Counter
from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import re
import sys

from blake3 import blake3

from paw.core.batch import read_source_bytes
from paw.core.job_registry import require_stopped_case
from paw.core.text_triage import TextCaseAssessor
from paw.core.verify import verify_case

DECISIONS = ('Inconclusive', 'Suspicious or compromised account', 'Likely malicious infrastructure')
PROFILES = ('default', 'strict', 'conservative')
TRIAGE_DECISIONS = ('no_supported_signal', 'not_evaluated', 'review')
TEXT_DECISIONS = ('below_threshold', 'not_evaluated', 'review')
TEXT_THRESHOLDS = (0.5, 0.9)


def read_labels(path):
    records = json.loads(path.read_text())
    if not isinstance(records, list) or not records:
        raise ValueError('Provide a nonempty independent corpus manifest')
    labels, groups = {}, {}
    for record in records:
        digest, split, label = (record[k] for k in ('sha256','split','label'))
        if not re.fullmatch('[a-f0-9]{64}', digest) or digest in labels:
            raise ValueError('Invalid or duplicate original digest')
        if split not in ('pilot','development','holdout') or label not in ('phishing','legitimate','unresolved'):
            raise ValueError('Invalid split or label')
        if label != 'unresolved' and not record.get('label_basis','').strip():
            raise ValueError('Resolved labels require a recorded independent basis')
        group = record['group']
        if not group.strip() or groups.setdefault(group, split) != split:
            raise ValueError('Missing group or group shared across corpus partitions')
        labels[digest] = record
    return labels


def _original_digests(path, *, include_blake3):
    with path.open('rb') as original:
        if not include_blake3:
            return hashlib.file_digest(original, 'sha256').hexdigest(), None
        sha = hashlib.sha256()
        seal = blake3()
        while chunk := original.read(1024**2):
            sha.update(chunk)
            seal.update(chunk)
        return sha.hexdigest(), seal.hexdigest()


def _report(outcomes, decisions, elevated, split, originals):
    matrix = {key: {d: outcomes[key,d] for d in decisions} for key in ('phishing','legitimate','unresolved')}
    result = {'originals':originals,'decisions_by_independent_label':matrix}
    if split == 'holdout':
        # Keep abstentions in the denominator. The referral rule only counts
        # explicit analyst referrals as positive decisions.
        for key, label, choices in (
                ('missed_referrals','phishing',set(decisions)-elevated),
                ('false_referrals','legitimate',elevated)):
            count = sum(matrix[label][choice] for choice in choices)
            denominator = sum(matrix[label].values())
            result[key] = {'count':count,'denominator':denominator,
                           'rate':count/denominator if denominator else None}
    return result


def evaluate(labels, directory, profile, split, *, static_triage=False, text_assessor=None):
    if static_triage and text_assessor is not None:
        raise ValueError('Choose static triage or text assessment')
    wanted = {k for k,v in labels.items() if v['split'] == split}
    if not wanted:
        raise ValueError(f'No cases designated for {split}')
    observed, outcomes = set(), Counter()
    decisions = TRIAGE_DECISIONS if static_triage else DECISIONS
    text_outcomes = {threshold: Counter() for threshold in TEXT_THRESHOLDS}
    model = None
    for case in sorted(directory.glob('case-*')):
        if case.is_symlink() or not case.is_dir():
            raise ValueError('Expected a local case directory')
        require_stopped_case(case)
        if not (case/'evidence/inventory_scope.json').is_file():
            raise ValueError('Complete inventory required to bind original, execution and score')
        with redirect_stdout(sys.stderr):
            if not verify_case(case):
                raise ValueError('Case evidence verification failed')
        root = None
        if text_assessor is not None:
            root = read_source_bytes(case/'evidence/merkle_root.bin', 128).decode('ascii').strip()
        key, original_blake3 = _original_digests(case/'input.eml', include_blake3=text_assessor is not None)
        if key not in labels:
            raise ValueError('Case missing from corpus manifest')
        if key not in wanted:
            continue
        if key in observed:
            raise ValueError('Duplicate evaluation case in a profile')
        execution = json.loads((case/'execution.json').read_text())
        score = json.loads((case/'report/score.json').read_text())
        if execution['status'] != 'completed' or score.get('profile') != profile:
            raise ValueError('Incomplete case or wrong profile')
        label = labels[key]['label']
        if text_assessor is not None:
            assessment = text_assessor.assess(case)
            evidence = assessment['evidence']
            if evidence['merkle_root_blake3'] != root or evidence['original_blake3'] != original_blake3:
                raise ValueError('Text assessment does not match the labelled case seal and original')
            model = assessment['model']
            for threshold, counter in text_outcomes.items():
                decision = 'not_evaluated'
                if assessment['status'] == 'completed':
                    decision = 'review' if assessment['scores']['fraud'] >= threshold else 'below_threshold'
                counter[label, decision] += 1
            observed.add(key)
            continue
        decision = score['decision']
        if static_triage:
            path = case/'mail_triage.json'
            if not path.is_file():
                raise ValueError('Static triage requires a saved mail_triage.json for each case')
            triage = json.loads(path.read_text())
            if not isinstance(triage, dict) or type(triage.get('schema_version')) is not int or triage['schema_version'] != 1:
                raise ValueError('Unsupported static triage schema')
            decision = triage.get('referral_status')
        if decision not in decisions:
            raise ValueError('Unrecognized saved decision')
        observed.add(key)
        outcomes[label, decision] += 1
    if observed != wanted:
        raise ValueError('Evaluation partition lacks saved decisions for one or more originals')
    if text_assessor is not None:
        return {'referral_rule':'horizon_fraud_score', 'model':model,
                'thresholds':{str(threshold): _report(counter, TEXT_DECISIONS, {'review'}, split, len(observed))
                              for threshold, counter in text_outcomes.items()}}
    elevated = {'review'} if static_triage else set(DECISIONS[1:])
    result = _report(outcomes, decisions, elevated, split, len(observed))
    if static_triage:
        result['referral_rule'] = 'static_mail_triage'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--split', choices=['pilot','development','holdout'], default='holdout')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--static-triage', action='store_true', help='Evaluate static review referrals')
    mode.add_argument('--text-model', type=Path, metavar='MODEL_DIR', help='Evaluate pinned local Horizon text scores')
    for profile in PROFILES:
        parser.add_argument('--'+profile, type=Path, metavar='CASES')
    args = parser.parse_args()
    profiles = {p: getattr(args,p) for p in PROFILES if getattr(args,p) is not None}
    if args.text_model is None and len(profiles) != len(PROFILES):
        parser.error('Supply --default, --strict and --conservative')
    if not profiles:
        parser.error('Supply at least one profile directory with --text-model')
    labels = read_labels(args.labels)
    assessor = TextCaseAssessor(args.text_model) if args.text_model is not None else None
    print(json.dumps({p:evaluate(labels,cases,p,args.split, static_triage=args.static_triage, text_assessor=assessor)
                      for p,cases in profiles.items()}, indent=2))
