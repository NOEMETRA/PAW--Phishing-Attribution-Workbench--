"""Additional fixed QEMU/port-loss probes; synthetic WAN only.

The bounded --cycle reproduces worker-loss handling, then waits for a Boolean
operator marker before a fresh process tests the corrected supervisor. It never
accepts a command or target from that marker. No persistent root helper remains.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback

sys.path.insert(0,str(Path(__file__).resolve().parent))
from gw_validation import Matrix, process_identity, fingerprints

def run_case(args,before):
    suffix='before' if before else 'after'
    args.output=args.root/suffix;matrix=Matrix(args)
    try:
        if not before:
            matrix.run(['/usr/bin/systemctl','set-property','--runtime','machine-paws14.slice','MemoryMax=2G'])
            shutil.copyfile(Path(__file__).with_name('machine-paws14.slice'),'/etc/systemd/system/machine-paws14.slice')
            matrix.run(['/usr/bin/systemctl','daemon-reload'])
        matrix.prepare()
        for case in (['worker-loss'] if before else ['worker-loss','gateway-loss','unexpected-port']):
            channels=matrix.job(case);channels['worker'].call('async_fetch');time.sleep(.4)
            active=matrix.active;trigger=time.monotonic()
            if case.endswith('loss'):
                role=case.split('-')[0];node=next(n for n in active['nodes'] if n['role']==role)
                scope=Path(node['actual']['scope'])
                active['record']['memory_accounting_before_fault']={p:(scope/p).read_text() for p in ['memory.current','memory.max','memory.events']}
                active['record']['qemu_oom_score_adj']=Path('/proc',str(node['actual']['pid']),'oom_score_adj').read_text().strip()
                # Force exactly this owned domain to exit. The earlier 64 MiB
                # injection did not kill QEMU and is retained as a failed
                # injection, never claimed as a passed OOM test.
                matrix.connection.lookupByUUIDString(node['uuid']).destroy()
                deadline=time.monotonic()+5
                while process_identity(node['actual']['pid'])==node['actual']['identity'] and time.monotonic()<deadline:time.sleep(.1)
                assert process_identity(node['actual']['pid'])!=node['actual']['identity'],'Selected QEMU did not stop'
                active['record']['lost_domain']={'role':role,'uuid':node['uuid'],'pid':node['actual']['pid']}
            else:
                matrix.run(['/usr/sbin/ip','link','add','pgw-rogue','type','veth','peer','name','pgw-roguep'])
                matrix.run(['/usr/sbin/ip','link','set','pgw-rogue','master','pawbr-int'])
                matrix.run(['/usr/sbin/ip','link','set','pgw-rogue','up'])
            stopped=matrix.stopped(seconds=6 if before else 12)
            active['record']['fault_oracle']={'fault':case,'all_writers_stopped_automatically':stopped,'latency_seconds':time.monotonic()-trigger}
            if before:
                assert not stopped,'The supposed defect did not reproduce'
                matrix.report['reproduced_unstopped_peer']=True
            else:assert stopped,'Unstopped peer after '+case
            matrix.finish(case)
            if case=='unexpected-port':matrix.run(['/usr/sbin/ip','link','del','pgw-rogue'])
            print(suffix+': '+case+' automatic stop='+str(stopped),flush=True)
        if not before:matrix.startup()
        matrix.report['result']='FAIL' if before else 'PASS'
    except Exception as error:
        matrix.report['error']=str(error);matrix.report['traceback']=traceback.format_exc();print(matrix.report['traceback'],flush=True)
    finally:
        if Path('/sys/class/net/pgw-rogue').exists():matrix.run(['/usr/sbin/ip','link','del','pgw-rogue'])
        try:matrix.cleanup()
        except Exception as error:matrix.report['cleanup_error']=str(error);matrix.report['result']='FAIL'
        matrix.report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        (matrix.output/'results.json').write_text(json.dumps(matrix.report,indent=2)+'\n')
        destination=args.export/suffix;destination.mkdir(mode=0o700,parents=True,exist_ok=False)
        for path in matrix.output.iterdir():
            if path.is_file() and (path.suffix in {'.log','.pcap','.xml'} or path.name in {'results.json','wan.jsonl','host-canary.jsonl'} or path.name.endswith('-result.json')):
                shutil.copyfile(path,destination/path.name);os.chown(destination/path.name,1000,1000)
        shutil.copytree(matrix.output/'sources',destination/'sources')
        for path in (destination/'sources').iterdir():os.chown(path,1000,1000)
        for path in [destination/'sources',destination,args.export]:os.chown(path,1000,1000)
    return matrix.report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--assets',type=Path,required=True)
    parser.add_argument('--export',type=Path,required=True);parser.add_argument('--marker',type=Path)
    parser.add_argument('--cycle',action='store_true');args=parser.parse_args()
    if args.cycle:
        assert args.marker and not args.marker.exists()
        # Recover only the empty named WAN left by the measured stale-handle
        # cleanup error, preserving the original FAIL evidence unchanged.
        import libvirt
        connection=libvirt.open('qemu:///system')
        try:
            assert not connection.listAllDomains(0)
            bridge=Path('/sys/class/net/pawbr-wan')
            ports=list((bridge/'brif').iterdir()) if bridge.exists() else []
            assert not ports,'Unexpected WAN members; do not recover blindly'
            initial={'scope':'Owned empty WAN recovery after libvirt restart','no_domains':True,'ports':[],
                     'guard_fingerprints':fingerprints(),'network_name':'paw-s14-wan','already_removed':not bridge.exists()}
            if bridge.exists():
                network=connection.networkLookupByName('paw-s14-wan')
                if network.isActive():network.destroy()
                network.undefine()
            assert not Path('/sys/class/net/pawbr-wan').exists()
            args.export.mkdir(parents=True,exist_ok=False,mode=0o700)
            (args.export/'empty-wan-recovery.json').write_text(json.dumps({**initial,'result':'PASS'},indent=2)+'\n')
            os.chown(args.export/'empty-wan-recovery.json',1000,1000);os.chown(args.export,1000,1000)
        finally:connection.close()
        report=run_case(args,True)
        assert report.get('reproduced_unstopped_peer') and not report.get('cleanup_error')
        print('WAITING_FOR_FIXED_SUPERVISOR_MARKER (180 seconds maximum)',flush=True)
        deadline=time.monotonic()+180
        while not args.marker.exists() and time.monotonic()<deadline:time.sleep(.5)
        assert args.marker.exists(),'No fixed-supervisor marker; exiting without further tests'
        command=['/usr/bin/python3','-I',str(Path(__file__).resolve()),'--root',str(args.root),'--assets',str(args.assets),'--export',str(args.export)]
        subprocess.run(command,check=True,timeout=900)
    else:
        report=run_case(args,False)
        if report['result']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
