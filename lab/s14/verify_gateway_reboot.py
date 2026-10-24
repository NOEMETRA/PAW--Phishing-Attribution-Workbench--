"""Read-only post-reboot guard check. Does not start guests or lab traffic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from gw_validation import fingerprints, BASE, digest

def require(value,reason):
    if not value:raise ValueError(reason)

def run(argv):
    value=subprocess.run(argv,capture_output=True,text=True,timeout=15)
    require(value.returncode==0,str(argv)+': '+value.stderr);return value.stdout.strip()

def verify(previous):
    import libvirt
    require(os.geteuid()==0,'root_read_access_required')
    report=json.loads(previous.read_text());require(report['result']=='PASS','previous_matrix_not_passed')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(boot!=report['host_inventory']['boot_id'],'same_boot_not_a_reboot_test')
    require(fingerprints()==report['final_filter_fingerprints'],'effective_guard_changed_or_missing')
    require(run(['/usr/bin/systemctl','is-active','paw-s14-guard.service'])=='active','guard_not_active')
    require(run(['/usr/bin/systemctl','is-enabled','paw-s14-guard.service'])=='enabled','guard_not_enabled')
    require(digest(Path('/etc/systemd/system/paw-s14-guard.service'))==report['persistent_guard']['unit_sha256'],'unit_changed')
    for name,sha in report['persistent_guard']['all_rules_sha256'].items():
        require(digest(Path('/etc/paw-s14')/name)==sha,'persistent_rule_changed:'+name)
    require(digest(BASE)=='b3296484e362ba2e713489a5de6225c719d9500962bde25d15f2f21e512c7658' and BASE.stat().st_uid==0 and BASE.stat().st_mode&0o777==0o444,'base_image_changed')
    dependencies=run(['/usr/bin/systemctl','show','libvirtd.service','-p','Requires','-p','After'])
    require(all('paw-s14-guard.service' in line for line in dependencies.splitlines()),'guard_dependency_missing')
    connection=libvirt.open('qemu:///system')
    try:
        require(not connection.listAllDomains(0),'unexpected_domain')
        networks=[]
        for network in connection.listAllNetworks(0):
            require(not network.autostart(),'unexpected_network_autostart:'+network.name())
            networks.append({'name':network.name(),'active':bool(network.isActive()),'autostart':False})
        require(not any(v['active'] for v in networks),'unexpected_active_network')
    finally:connection.close()
    for bridge in ['pawbr-int','pawbr-wan']:
        require(not Path('/sys/class/net',bridge).exists(),'unexpected_bridge_after_reboot:'+bridge)
    require(not Path('/run/netns/pawgwan').exists(),'fixture_namespace_survived')
    qemu=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            data=(proc/'cmdline').read_bytes()
            if b'qemu-system-' in data.split(b'\0')[0]:qemu.append(proc.name)
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    require(not qemu,'qemu_survived_or_autostarted')
    guard_time=int(run(['/usr/bin/systemctl','show','paw-s14-guard.service','-p','ActiveEnterTimestampMonotonic','--value']))
    daemon_time=int(run(['/usr/bin/systemctl','show','libvirtd.service','-p','ActiveEnterTimestampMonotonic','--value']))
    require(0<guard_time<=daemon_time,'startup_order_not_observed')
    return {'result':'PASS','scope':'Post-reboot closed-profile startup only; no real egress or detonation',
            'previous_boot_id':report['host_inventory']['boot_id'],'boot_id':boot,'utc':time.time(),
            'guard_active_before_libvirt':True,'guard_active_monotonic_us':guard_time,'libvirt_active_monotonic_us':daemon_time,
            'domains':[],'qemu_pids':[],'networks':networks,'filter_fingerprints':fingerprints(),
            'real_target_acceptance':'not_authorized_or_validated'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('previous_results',type=Path);args=parser.parse_args()
    print(json.dumps(verify(args.previous_results),indent=2))
