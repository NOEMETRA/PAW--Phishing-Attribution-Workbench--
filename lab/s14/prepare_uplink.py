"""Capture the current Wi-Fi binding and render disabled files, without DNS/egress."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from uplink_policy import (make_profile,guard_tables,nat_table,bridge_table,
                           interop_commands,live_readiness,fingerprint)

def current_uplink():
    routes=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','route']))
    defaults=[r for r in routes if r.get('dst')=='default']
    if len(defaults)!=1:raise ValueError('Ambiguous default route')
    route=defaults[0];device=route['dev']
    if not (Path('/sys/class/net')/device/'wireless').exists():raise ValueError('Current uplink is not Wi-Fi')
    address=json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address','show',device]))[0]
    link=subprocess.check_output(['/usr/sbin/iw','dev',device,'link'],text=True)
    found=re.search(r'^Connected to ([0-9a-f:]{17}) ',link,re.M)
    if not found:raise ValueError('Wi-Fi not associated')
    uuid=subprocess.check_output(['/usr/bin/nmcli','-g','GENERAL.CON-UUID','device','show',device],text=True).strip()
    return {'interface':device,'mac':address['address'],'host_ipv4':route['prefsrc'],'next_hop':route['gateway'],
            'connection_uuid':uuid,'bssid':found.group(1)}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    observed=current_uplink();profile=make_profile(**observed)
    files={'profile.json':json.dumps(profile,indent=2)+'\n',
           'host-guards.nft':guard_tables(profile)+bridge_table(profile),
           'nat.nft':nat_table(profile),'docker-user-commands.json':json.dumps(interop_commands(profile),indent=2)+'\n',
           'readiness.json':json.dumps(live_readiness(profile),indent=2)+'\n',
           'uplink-network.xml':"<network><name>paw-s14-uplink</name><forward mode='bridge'/><bridge name='pawbr-up'/><dns enable='no'/></network>\n",
           'freeze.json':json.dumps({'profile_sha256':fingerprint(profile),'real_dns_queries':0,'installed':False,'enabled':False},indent=2)+'\n'}
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    for name,data in files.items():(args.output/name).write_text(data)
    print(json.dumps({'result':'PREPARED_NOT_ACTIVE','profile_sha256':fingerprint(profile),'files':list(files),'target':profile['targets'][0]['url'],'real_dns_queries':0,'live_connections_opened':0}))

if __name__=='__main__':main()
