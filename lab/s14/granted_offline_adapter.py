"""Single-use adapter for explicit root grants of owned harmless fixtures only."""
import xml.etree.ElementTree as ET
import time

from offline_candidate import canonical, require
from offline_input_matrix import InputGate, _run_admitted_job
from one_use_authorization import (consume, load_bound, confirm_consumed, execution_lock, digest)
from i08_context import capture
from owned_grant_fixtures import CPU_DISABLED


class GrantedGate(InputGate):
    def validate_runtime(self, runtime):
        disabled = {item.get('name') for item in runtime.findall('cpu/feature') if item.get('policy') == 'disable'}
        require(set(CPU_DISABLED) <= disabled, 'effective_cpu_features_not_disabled')

    def descriptor(self, *args, **kwargs):
        node = super().descriptor(*args, **kwargs)
        xml = ET.fromstring(node['xml'].read_bytes())
        cpu = xml.find('cpu')
        require(cpu is not None, 'explicit_cpu_policy_required')
        for name in CPU_DISABLED:
            ET.SubElement(cpu, 'feature', {'policy': 'disable', 'name': name})
        node['xml'].write_bytes(ET.tostring(xml))
        return node


def run_granted(gate, raw, policy_raw, cancel=False):
    """No caller-selectable admission hook; consumes global authority before VM."""
    require(isinstance(gate, GrantedGate), 'granted_gate_required')
    if getattr(gate, 'active_vm', None) is not None:
        raise ValueError('gate_busy')
    with execution_lock():
        ledger, grant_raw, summary, value, source = consume(raw, policy_raw, capture())
        # Detached job for the existing seed/controller/lifecycle. It is not
        # admitted by the legacy synthetic string/catalog API.
        job = {'profile': summary['profile'], 'job_id': 'grant-' + summary['request_id'],
               'parent_sha256': summary['case_reference_sha256'], 'source_hex': source.hex(),
               'source_sha256': summary['source_sha256'], 'operator_authorization': 'root-owned-synthetic-grant-v1',
               'created_at': value['created_at'], 'expires_at': value['expires_at']}
        current = {'job': job, 'source': source, 'job_sha256': digest(canonical(job))}
        admission = {}
        def revalidate():
            reread, checked, _, checked_source = load_bound(raw, policy_raw, capture())
            require(reread == grant_raw and checked == summary and checked_source == source, 'grant_changed_after_boot')
            confirm_consumed(ledger)
            admission['at'] = int(time.time())
        result = _run_admitted_job(gate, current, revalidate, cancel)
        result.update(candidate_frame_sha256=digest(raw), candidate_sha256=summary['candidate_sha256'],
                      grant_sha256=digest(grant_raw), policy_sha256=digest(policy_raw), consumption=ledger,
                      admitted_at=admission['at'])
        return result
