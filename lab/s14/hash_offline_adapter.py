"""Hash-authorized offline Python execution; no source catalogue in this path."""
import time
import shutil
from pathlib import Path
import xml.etree.ElementTree as ET

from offline_candidate import canonical,require
from offline_input_matrix import _run_admitted_job
from granted_offline_adapter import GrantedGate
from one_use_authorization import execution_lock
from benign_guest_validation import BASE
import hash_authorization as authority


class HashGate(GrantedGate):
    def descriptor(self,role,case,*args,**kwargs):
        case='authorized-'+case.removeprefix('synthetic-')
        node=super().descriptor(role,case,*args,**kwargs)
        xml=ET.fromstring(node['xml'].read_bytes())
        backing=xml.find('memoryBacking')
        if backing is None:backing=ET.SubElement(xml,'memoryBacking')
        ET.SubElement(backing,'nosharepages')
        features=xml.find('features');ET.SubElement(features,'pmu',{'state':'off'})
        ET.SubElement(features,'vmport',{'state':'off'})
        devices=xml.find('devices')
        for child in list(devices):
            if child.tag=='controller' and child.get('type')=='usb':devices.remove(child)
        ET.SubElement(devices,'controller',{'type':'usb','model':'none'})
        node['xml'].write_bytes(ET.tostring(xml));return node

    def validate_runtime(self,runtime):
        super().validate_runtime(runtime)
        require(runtime.find('memoryBacking/nosharepages') is not None and
                runtime.find('features/pmu').get('state')=='off' and runtime.find('features/vmport').get('state')=='off',
                'hash_memory_or_cpu_surface')
        require(all(v.get('model')=='none' for v in runtime.findall('devices/controller') if v.get('type')=='usb'),'usb_not_disabled')
        vm=self.active_vm;pid=vm['actual']['pid']
        observed=authority.fs.digest(Path('/proc',str(pid),'exe').read_bytes())
        require(observed==self.hash_context['qemu_binary_sha256'],'running_qemu_binary_changed')
        command=Path('/proc',str(pid),'cmdline').read_bytes()
        require(b'mem-merge=off' in command or b'"merge":false' in command,'qemu_memory_merge_not_disabled')
        vm['actual'].update(qemu_binary_sha256=observed,memory_merge_disabled=True)


def run_hash_granted(gate,raw,policy_raw,cancel=False):
    require(isinstance(gate,HashGate),'hash_gate_required')
    if getattr(gate,'active_vm',None) is not None:raise ValueError('gate_busy')
    require(shutil.disk_usage(BASE.parent).free>=10*1024**3,'host_disk_admission')
    # Shared lock with the historical root adapter, separate v2 authority store.
    with execution_lock():
        context=authority.capture();ledger,grant_raw,summary,value,source=authority.consume(raw,policy_raw,context)
        gate.hash_context=context
        job={'profile':summary['profile'],'job_id':'hash-'+summary['request_id'],
             'parent_sha256':summary['case_reference_sha256'],'source_hex':source.hex(),
             'source_sha256':summary['source_sha256'],'operator_authorization':'root-hash-grant-v2',
             'created_at':value['created_at'],'expires_at':value['expires_at']}
        current={'job':job,'source':source,'job_sha256':authority.digest(canonical(job))};admitted={}
        def revalidate():
            reread,checked,_,content=authority.load_bound(raw,policy_raw,authority.capture())
            require(reread==grant_raw and checked==summary and content==source,'hash_grant_changed_after_boot')
            authority.confirm_consumed(ledger);admitted['at']=int(time.time())
        def before_publish():
            reread,checked,_,content=authority.load_bound(raw,policy_raw,authority.capture(),now=admitted['at'])
            require(reread==grant_raw and checked==summary and content==source,'hash_authority_changed_before_publication')
            authority.confirm_consumed(ledger)
        result=_run_admitted_job(gate,current,revalidate,cancel,before_publish)
        result.update(candidate_frame_sha256=authority.digest(raw),candidate_sha256=summary['candidate_sha256'],
                      grant_sha256=authority.digest(grant_raw),policy_sha256=authority.digest(policy_raw),
                      execution_purpose=__import__('json').loads(grant_raw)['execution_purpose'],
                      consumption=ledger,admitted_at=admitted['at'])
        return result
