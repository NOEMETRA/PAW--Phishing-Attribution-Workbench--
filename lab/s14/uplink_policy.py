"""Prepare-only Wi-Fi routed uplink and exact target admission.

Validation/compilation uses no DNS, sockets, shell execution or rule installation;
admission reads the monotonic clock and current kernel boot identifier. The
operator-facing profile stays disabled and has no admitted address by default.
The old, measured offline gateway/engine is not changed by this module.
"""
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import time
import urllib.parse

from gw_admission import Refused, require, strict_json

HOST = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z')
INTERFACE = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}\Z')
IDENTIFIER = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z')
# Conservatively deny whole special-purpose blocks, even their public exceptions.
# This intentionally does not depend on Python-maintenance-version is_global.
DENIED = tuple(ipaddress.ip_network(value) for value in (
    '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8',
    '169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24',
    '192.88.99.0/24','192.168.0.0/16','198.18.0.0/15',
    '198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4'))
FIXTURE = '198.18.43.10'

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

def exact(value,keys,label):
    require(type(value)is dict and set(value)==set(keys),label+'_shape')

def integer(value,low,high,label):
    require(type(value)is int and low<=value<=high,label)

def address(value,emulation=False):
    require(type(value)is str,'ipv4_type')
    try:parsed=ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:raise Refused('ipv4_literal') from error
    require(str(parsed)==value,'ipv4_noncanonical')
    if emulation:
        require(value==FIXTURE,'only_owned_fixture');return value
    require(not any(parsed in network for network in DENIED),'special_purpose_ipv4')
    return value

def endpoint(value):
    require(type(value)is str and 0<len(value)<=2048,'url_size')
    require(not any(ord(c)<=32 or ord(c)>=127 for c in value) and '\\' not in value,'url_characters')
    try:p=urllib.parse.urlsplit(value);port=p.port;host=p.hostname
    except ValueError as error:raise Refused('url_parse') from error
    require(p.scheme=='https' and host and HOST.fullmatch(host),'https_hostname')
    require(p.username is None and p.password is None and not p.fragment and not p.query,'url_authority_or_query')
    require('%' not in p.netloc and '[' not in p.netloc and '@' not in p.netloc,'url_literal_or_encoded_authority')
    require(p.netloc==host or p.netloc==host+':443','url_noncanonical_authority')
    require(port in {None,443} and not re.search(r'%|[\x00-\x20]',p.path),'url_path_or_port')
    path=p.path or '/'
    require(path.startswith('/') and not path.startswith('//') and all(x not in {'.','..'} for x in path.split('/')),'url_path')
    return {'host':host,'port':443,'path':path,'url':'https://'+host+path}

def validate(profile):
    exact(profile,{'schema','mode','enabled','uplink','gateway','budgets','targets'},'profile')
    require(type(profile['schema'])is int and profile['schema']==1 and profile['mode'] in {'wifi-routed','emulation'},'schema_or_mode')
    require(profile['enabled'] is False,'prepare_only_profile_must_be_disabled')
    exact(profile['uplink'],{'interface','mac','host_ipv4','next_hop','connection_uuid','bssid'},'uplink')
    uplink=profile['uplink']
    require(type(uplink['interface'])is str and INTERFACE.fullmatch(uplink['interface']),'uplink_interface')
    require(type(uplink['mac'])is str and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',uplink['mac']),'uplink_mac')
    if profile['mode']=='wifi-routed':
        require(type(uplink['connection_uuid'])is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',uplink['connection_uuid']),'connection_uuid')
        require(type(uplink['bssid'])is str and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',uplink['bssid']),'wifi_bssid')
    else:require(uplink['connection_uuid'] is None and uplink['bssid'] is None,'emulation_has_no_wifi')
    for key in ['host_ipv4','next_hop']:
        require(type(uplink[key])is str,'uplink_address_type')
        try:ipaddress.IPv4Address(uplink[key])
        except ipaddress.AddressValueError as error:raise Refused('uplink_address') from error
    exact(profile['gateway'],{'interface','source_ipv4','router_ipv4','tap','mac'},'gateway')
    gateway=profile['gateway']
    for key in ['interface','tap']:require(type(gateway[key])is str and INTERFACE.fullmatch(gateway[key]),'gateway_interface')
    require(gateway['source_ipv4']=='198.18.41.2' and gateway['router_ipv4']=='198.18.41.1','fixed_gateway_link')
    require(gateway['mac']=='52:54:00:14:41:02','gateway_mac')
    require(gateway['interface']!=uplink['interface'],'interface_collision')
    exact(profile['budgets'],{'lease_seconds','request_count','response_bytes','job_seconds','redirects'},'budgets')
    integer(profile['budgets']['lease_seconds'],1,10,'lease_seconds')
    integer(profile['budgets']['request_count'],1,4,'request_count')
    integer(profile['budgets']['response_bytes'],1,65536,'response_bytes')
    integer(profile['budgets']['job_seconds'],1,60,'job_seconds')
    require(profile['budgets']['redirects']==0,'redirects_disabled_for_initial_profile')
    require(type(profile['targets'])is list and len(profile['targets'])<=4,'target_count')
    ids=set();urls=set()
    for target in profile['targets']:
        exact(target,{'id','url','method','purpose','authorization_ref','pinned_ipv4'},'target')
        require(type(target['id'])is str and IDENTIFIER.fullmatch(target['id']) and target['id'] not in ids,'target_id')
        ids.add(target['id']);parsed=endpoint(target['url'])
        require(parsed['url']==target['url'] and target['url'] not in urls,'target_url_canonical_or_duplicate');urls.add(target['url'])
        require(target['method']=='GET','method')
        for key in ['purpose','authorization_ref']:require(type(target[key])is str and 0<len(target[key])<=512,'target_reference')
        require(type(target['pinned_ipv4'])is list and len(target['pinned_ipv4'])<=4,'pin_count')
        require(all(type(v)is str for v in target['pinned_ipv4']),'pin_type')
        require(len(set(target['pinned_ipv4']))==len(target['pinned_ipv4']),'duplicate_pin')
        for value in target['pinned_ipv4']:address(value,profile['mode']=='emulation')
    return copy.deepcopy(profile)

def admit(profile,target_id,url,answers,dns_age_seconds,ttl_seconds,remaining_seconds):
    """Admit supplied DNS observations; never performs a DNS query or opens a lease."""
    profile=validate(profile)
    require(type(target_id)is str,'target_id')
    matches=[t for t in profile['targets'] if t['id']==target_id]
    require(len(matches)==1,'target_not_registered');target=matches[0]
    require(endpoint(url)['url']==target['url'],'request_out_of_exact_url_scope')
    require(target['pinned_ipv4'],'address_pinning_pending')
    require(type(answers)is list and 0<len(answers)<=4 and all(type(v)is str for v in answers) and len(set(answers))==len(answers),'dns_answer_count')
    for value in answers:
        address(value,profile['mode']=='emulation');require(value in target['pinned_ipv4'],'dns_rebinding_or_unapproved_address')
    for value in [dns_age_seconds,ttl_seconds,remaining_seconds]:require(type(value)in {int,float} and math.isfinite(value),'nonfinite_dns_or_job_time')
    require(0<=dns_age_seconds<min(ttl_seconds,10) and ttl_seconds<=3600 and remaining_seconds>0,'stale_dns_or_expired_job')
    lifetime=min(profile['budgets']['lease_seconds'],ttl_seconds-dns_age_seconds,remaining_seconds)
    require(lifetime>=1,'insufficient_lease_lifetime')
    issued=time.monotonic();duration=int(lifetime)
    return {'profile_sha256':fingerprint(profile),'target_id':target_id,'url':target['url'],
            'host':endpoint(url)['host'],'port':443,'address':answers[0],
            'all_addresses':answers,'lease_seconds':duration,'method':'GET',
            'issued_monotonic':issued,'expires_monotonic':issued+duration,'boot_id':boot_id(),
            'tls_hostname':endpoint(url)['host'],'redirects':0,
            'authorization_ref':target['authorization_ref'],'ownership_or_dnssec_verification':'not_established_by_this_record'}

def guard_tables(profile):
    """Two independent, empty timed guards. No broad established-flow exception."""
    p=validate(profile);inside=p['gateway']['interface'];outside=p['uplink']['interface'];source=p['gateway']['source_ipv4']
    reserved=', '.join(str(n) for n in DENIED if not (p['mode']=='emulation' and str(n)=='198.18.0.0/15'))
    output_drop=f'oifname "{inside}" counter drop;'
    if p['mode']=='emulation':output_drop+=f' oifname "{outside}" counter drop;'
    result=[]
    for name,priority in [('paw_s14_up_floor',-340),('paw_s14_up_lease',-330)]:
        result.append(f'''add table inet {name}
flush table inet {name}
table inet {name} {{
 set targets4 {{ type ipv4_addr . inet_service; flags timeout; timeout 10s; size 4; }}
 set denied4 {{ type ipv4_addr; flags interval; elements = {{ {reserved} }}; }}
 chain early {{
  type filter hook prerouting priority -450; policy accept;
  iifname "{inside}" meta nfproto ipv6 counter drop
  iifname "{inside}" ip frag-off & 0x3fff != 0 counter drop
 }}
 chain input {{ type filter hook input priority {priority}; policy accept; iifname "{inside}" counter drop; }}
 chain output {{ type filter hook output priority {priority}; policy accept; {output_drop} }}
 chain forward {{
  type filter hook forward priority {priority}; policy accept;
  iifname "{inside}" ip daddr @denied4 counter drop
  oifname "{inside}" ip saddr @denied4 counter drop
  iifname "{inside}" oifname "{outside}" ip saddr {source} ip daddr . tcp dport @targets4 ct state {{ new, established }} counter accept
  iifname "{outside}" oifname "{inside}" ip daddr {source} ip saddr . tcp sport @targets4 ct state established counter accept
  iifname "{inside}" counter drop
  oifname "{inside}" counter drop
 }}
}}
''')
    return '\n'.join(result)

def nat_table(profile):
    p=validate(profile)
    return f'''add table ip paw_s14_up_nat
flush table ip paw_s14_up_nat
table ip paw_s14_up_nat {{
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr {p['gateway']['source_ipv4']} oifname "{p['uplink']['interface']}" counter masquerade
 }}
}}
'''

def bridge_table(profile):
    p=validate(profile);bridge=p['gateway']['interface'];tap=p['gateway']['tap'];mac=p['gateway']['mac']
    return f'''add table bridge paw_s14_up_link
flush table bridge paw_s14_up_link
table bridge paw_s14_up_link {{
 chain ingress {{ type filter hook prerouting priority -420; policy accept;
  meta ibrname "{bridge}" iifname "{tap}" ether saddr {mac} ether type arp arp saddr ether {mac} arp saddr ip 198.18.41.2 arp daddr ip 198.18.41.1 counter accept
  meta ibrname "{bridge}" iifname "{tap}" ether saddr {mac} ether daddr 52:54:00:14:41:01 ether type ip ip saddr 198.18.41.2 ip frag-off & 0x3fff == 0 tcp dport 443 counter accept
  meta ibrname "{bridge}" counter drop
 }}
 chain forward {{ type filter hook forward priority -420; policy accept;
  meta ibrname "{bridge}" counter drop
  meta obrname "{bridge}" counter drop
 }}
}}
'''

def make_profile(interface,mac,host_ipv4,next_hop,connection_uuid=None,bssid=None,emulation=False):
    return validate({'schema':1,'mode':'emulation' if emulation else 'wifi-routed','enabled':False,
        'uplink':{'interface':interface,'mac':mac,'host_ipv4':host_ipv4,'next_hop':next_hop,'connection_uuid':connection_uuid,'bssid':bssid},
        'gateway':{'interface':'up0' if emulation else 'pawbr-up','source_ipv4':'198.18.41.2','router_ipv4':'198.18.41.1',
                   'tap':'gw-tap' if emulation else 'pu-gw','mac':'52:54:00:14:41:02'},
        'budgets':{'lease_seconds':5,'request_count':1,'response_bytes':8192,'job_seconds':30,'redirects':0},
        'targets':[{'id':'owned-fixture' if emulation else 'httpbingo-get',
                    'url':'https://allow.fixture.invalid/get' if emulation else 'https://httpbingo.org/get','method':'GET',
                    'purpose':'Owned isolated fixture' if emulation else 'One benign public HTTP testing-service GET; no user data',
                    'authorization_ref':'owned local fixture' if emulation else 'User delegated benign-domain selection, 2026-10-24; public service https://github.com/mccutchen/go-httpbin',
                    'pinned_ipv4':[FIXTURE] if emulation else []}]})

def match_uplink(profile,observed):
    p=validate(profile);require(type(observed)is dict and observed==p['uplink'],'uplink_changed')
    return True

def interop_commands(profile):
    p=validate(profile);inside=p['gateway']['interface'];outside=p['uplink']['interface'];source=p['gateway']['source_ipv4']
    # Use the documented user extension, never edit Docker-managed chains.
    return [
        ['/usr/sbin/iptables','-w','5','-I','DOCKER-USER','1','-i',inside,'-o',outside,'-s',source+'/32','-m','comment','--comment','paw-s14-uplink-prepared','-j','ACCEPT'],
        ['/usr/sbin/iptables','-w','5','-I','DOCKER-USER','1','-i',outside,'-o',inside,'-d',source+'/32','-m','comment','--comment','paw-s14-uplink-prepared','-j','ACCEPT']]

def lease_transaction(profile,plan):
    p=validate(profile)
    exact(plan,{'profile_sha256','target_id','url','host','port','address','all_addresses','lease_seconds','method','tls_hostname','redirects','authorization_ref','ownership_or_dnssec_verification','issued_monotonic','expires_monotonic','boot_id'},'plan')
    require(plan['profile_sha256']==fingerprint(p),'plan_profile_mismatch')
    matches=[t for t in p['targets'] if t['id']==plan['target_id']]
    require(len(matches)==1,'plan_target')
    target=matches[0];parsed=endpoint(target['url'])
    require(plan['url']==target['url'] and plan['host']==parsed['host'] and plan['tls_hostname']==parsed['host'],'plan_url_binding')
    require(plan['method']=='GET' and plan['redirects']==0 and plan['authorization_ref']==target['authorization_ref'],'plan_scope')
    require(type(plan['all_addresses'])is list and 0<len(plan['all_addresses'])<=4 and all(type(v)is str and v in target['pinned_ipv4'] for v in plan['all_addresses']),'plan_address_binding')
    require(plan['address']==plan['all_addresses'][0],'plan_peer_binding')
    address(plan['address'],p['mode']=='emulation');integer(plan['lease_seconds'],1,p['budgets']['lease_seconds'],'plan_lifetime')
    require(plan['port']==443,'plan_port')
    now=time.monotonic()
    for value in [plan['issued_monotonic'],plan['expires_monotonic']]:require(type(value)in {int,float} and math.isfinite(value),'plan_clock')
    require(plan['boot_id']==boot_id(),'plan_from_other_boot')
    require(plan['expires_monotonic']==plan['issued_monotonic']+plan['lease_seconds'],'plan_deadline_binding')
    require(plan['issued_monotonic']<=now<plan['expires_monotonic'],'stale_plan')
    remaining_ms=int((plan['expires_monotonic']-now)*1000)
    require(remaining_ms>0,'stale_plan')
    # Trusted controller only; callers cannot use this to install or renew rules.
    return ''.join(f"add element inet {table} targets4 {{ {plan['address']} . 443 timeout {remaining_ms}ms }}\n"
                   for table in ['paw_s14_up_floor','paw_s14_up_lease'])

def live_readiness(profile):
    p=validate(profile)
    return {'mode':p['mode'],'enabled':False,'status':'PREPARED_NOT_ACTIVE',
            'candidate_targets':[{'id':t['id'],'url':t['url'],'address_binding':'PINNED' if t['pinned_ipv4'] else 'PENDING'} for t in p['targets']],
            'blockers':['Explicit live activation is outside this prepare-only command',
                        'Current host/route/guard fingerprint and KVM integration acceptance required',
                        'Fresh reviewed public DNS address bindings required' if any(not t['pinned_ipv4'] for t in p['targets']) else 'Live traffic test not performed'],
            'live_connections_opened':0}
