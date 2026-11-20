"""Evaluate saved PAW decisions against a separately adjudicated holdout manifest."""
import argparse
from collections import Counter
from contextlib import redirect_stdout
import hashlib
import json
from pathlib import Path
import re
import sys

from paw.core.job_registry import require_stopped_case
from paw.core.verify import verify_case

DECISIONS = ('Inconclusive', 'Suspicious or compromised account', 'Likely malicious infrastructure')
PROFILES = ('default', 'strict', 'conservative')


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


def evaluate(labels, directory, profile, split):
    wanted = {k for k,v in labels.items() if v['split'] == split}
    if not wanted:
        raise ValueError(f'No cases designated for {split}')
    observed, outcomes = set(), Counter()
    for case in sorted(directory.glob('case-*')):
        if case.is_symlink() or not case.is_dir():
            raise ValueError('Expected a local case directory')
        require_stopped_case(case)
        if not (case/'evidence/inventory_scope.json').is_file():
            raise ValueError('Complete inventory required to bind original, execution and score')
        with redirect_stdout(sys.stderr):
            if not verify_case(case):
                raise ValueError('Case evidence verification failed')
        with (case/'input.eml').open('rb') as original:
            key = hashlib.file_digest(original, 'sha256').hexdigest()
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
        if score['decision'] not in DECISIONS:
            raise ValueError('Unrecognized score decision')
        observed.add(key)
        outcomes[labels[key]['label'], score['decision']] += 1
    if observed != wanted:
        raise ValueError('Evaluation partition lacks saved decisions for one or more originals')
    matrix = {key: {d: outcomes[key,d] for d in DECISIONS} for key in ('phishing','legitimate','unresolved')}
    result = {'originals':len(observed),'decisions_by_independent_label':matrix}
    if split == 'holdout':
        # Defined task: send either elevated engine decision to analyst review.
        # An inconclusive phishing original is missed by this referral rule.
        for key, label, decisions in [('missed_referrals','phishing',DECISIONS[:1]),
                                      ('false_referrals','legitimate',DECISIONS[1:])]:
            count = sum(matrix[label][d] for d in decisions)
            denominator = sum(matrix[label].values())
            result[key] = {'count':count,'denominator':denominator,
                           'rate':count/denominator if denominator else None}
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--split', choices=['pilot','development','holdout'], default='holdout')
    for profile in PROFILES:
        parser.add_argument('--'+profile, type=Path, required=True, metavar='CASES')
    args = parser.parse_args()
    labels = read_labels(args.labels)
    print(json.dumps({p:evaluate(labels,getattr(args,p),p,args.split) for p in PROFILES}, indent=2))
