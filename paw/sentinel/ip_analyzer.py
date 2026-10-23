"""Bounded IP syntax and unverified provider observations, without identity/risk inference."""
import base64
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import copy
import ipaddress
import json
import os
import threading
import time
from urllib.parse import quote, urlsplit

from .contracts import _require_active, _json_tree, _json_chunks
from .transport import fetch_http, positive_number, native_integer
from ..deobfuscate.url import http_url_status


class IPAnalyzer:
    def __init__(self, timeout=10, use_proxy=True, proxy_url=None, *, provider_urls=None, ptr_resolver=None):
        positive_number(timeout,'timeout',300)
        if type(use_proxy) is not bool: raise ValueError('use_proxy requires a native boolean')
        self.timeout = timeout; self.use_proxy = use_proxy
        self.proxy_url = proxy_url if proxy_url is not None else os.environ.get('PAW_PROXY_URL')
        if self.proxy_url is not None and (type(self.proxy_url) is not str or http_url_status(self.proxy_url)[0]!='completed'):
            raise ValueError('An absolute HTTP(S) proxy URL is required')
        self.proxies = {'http':self.proxy_url,'https':self.proxy_url} if use_proxy and self.proxy_url else None
        defaults = {'ip-api':'http://ip-api.com/json','ipify':'https://geo.ipify.org/api/v2/country,city'}
        if provider_urls is not None:
            if type(provider_urls) is not dict or any(key not in defaults or type(value) is not str or
                    http_url_status(value)[0]!='completed' or
                    urlsplit(value).query or urlsplit(value).fragment or '@' in urlsplit(value).netloc
                    for key,value in provider_urls.items()):
                raise ValueError('Known provider names and absolute HTTP(S) endpoints required')
            defaults.update(provider_urls)
        self.provider_urls = defaults
        self.geolocation_cache = OrderedDict(); self.whois_cache = {}
        self._cache_lock = threading.RLock(); self._cache_bytes = 0
        self._ptr_resolver = ptr_resolver

    @staticmethod
    def _literal(value):
        if type(value) is not str or not 0 < len(value) <= 45 or '%' in value:
            raise ValueError('An unscoped textual IP literal is required')
        try: return ipaddress.ip_address(value)
        except ValueError: raise ValueError('An unscoped textual IP literal is required') from None

    def get_network_info(self, ip):
        address = self._literal(ip); prefix = 24 if address.version == 4 else 64
        return {'ip':ip,'canonical_ip':str(address),'is_private':address.is_private,
            'is_global':address.is_global,'is_loopback':address.is_loopback,'is_multicast':address.is_multicast,
            'network':str(ipaddress.ip_network(f'{address}/{prefix}',strict=False)),
            'version':address.version,'prefix_length':prefix,'verified':False,
            'scope':'Address syntax flags and assumed grouping prefix; not an allocated subnet, ASN or identity'}

    def analyze_ip(self, ip):
        _require_active(); self._literal(ip)
        result = {'ip':ip,'analysis_time':time.time(),'network_info':self.get_network_info(ip),
            'geolocation':{},'reverse_dns':None,'whois':{},'risk_indicators':[],'correlated_ips':[],
            'verified':False,'status':'partial','availability':{}}
        try:
            result['reverse_dns'] = self.reverse_dns_lookup(ip)
            result['availability']['reverse_dns'] = 'unverified_observation' if result['reverse_dns'] else 'unavailable'
        except Exception as error:
            result['availability']['reverse_dns'] = type(error).__name__
        result['geolocation'] = self.geolocate_ip(ip)
        result['availability']['geolocation'] = result['geolocation']['status']
        result['whois'] = self.whois_lookup(ip)
        result['availability'].update(whois='unavailable',risk='unavailable',identity='unavailable',correlation='unavailable')
        result['limitation'] = 'Provider/PTR claims are unverified; no validated IP risk, person/operator identity or attacker attribution'
        return result

    def reverse_dns_lookup(self, ip):
        _require_active(); address = self._literal(ip)
        try:
            import dns.resolver
            import dns.reversename
            resolver = self._ptr_resolver if self._ptr_resolver is not None else dns.resolver
            answer = resolver.resolve(dns.reversename.from_address(str(address)),'PTR',lifetime=self.timeout)
            return str(next(iter(answer))).rstrip('.')
        except ImportError:
            return None
        except Exception:
            from ..core.network_policy import network_allowed
            if not network_allowed(): raise
            return None

    @staticmethod
    def _json_payload(observation):
        def unique(pairs):
            value = {}
            for key,item in pairs:
                if key in value: raise ValueError('Duplicate provider JSON key')
                value[key] = item
            return value
        def invalid(value): raise ValueError('Nonfinite provider JSON number')
        return _json_tree(json.loads(observation['body'].decode('utf-8'),object_pairs_hook=unique,
                                    parse_constant=invalid),depth=32,nodes=10000)

    def _provider(self, name, ip):
        _require_active(); address = self._literal(ip)
        endpoint = self.provider_urls[name]
        params = None
        if name == 'ip-api': endpoint = endpoint.rstrip('/')+'/'+quote(str(address),safe='')
        else:
            key = os.environ.get('PAW_IPIFY_API_KEY')
            if not key:
                return {'status':'unavailable','source':name,'verified':False,'reason':'Provider credential unavailable'}
            params = {'apiKey':key,'ipAddress':str(address)}
        observation = fetch_http(endpoint,timeout=self.timeout,max_bytes=128*1024,proxies=self.proxies,params=params)
        body = observation.pop('body')
        evidence = {**observation,'body_base64':base64.b64encode(body).decode('ascii')}
        result = {'status':'unavailable','source':name,'ip':ip,'verified':False,'provider_evidence':evidence}
        if (observation['status'] != 'observed' or observation['http_status'] != 200 or observation['body_status']!='completed'
                or observation.get('content_encoding','identity').casefold() not in ('','identity')):
            result['reason'] = 'Provider response unavailable, unsuccessful or limited'; return result
        try:
            payload = self._json_payload({'body':body})
            if type(payload) is not dict: raise ValueError('Provider JSON object required')
            result['provider_payload'] = payload
            returned = payload.get('query' if name == 'ip-api' else 'ip')
            if self._literal(returned) != address: raise ValueError('Provider IP does not match request')
            if name == 'ip-api':
                if payload.get('status') != 'success': raise ValueError('Provider did not report success')
                values = payload
                mapping = {'country':'country','country_code':'countryCode','city':'city','region':'regionName',
                           'isp':'isp','org':'org','as':'as','timezone':'timezone','lat':'lat','lon':'lon'}
            else:
                values = payload.get('location')
                if type(values) is not dict: raise ValueError('Provider location object required')
                mapping = {'country':'country','country_code':'country','city':'city','region':'region','lat':'lat','lon':'lng'}
            omissions = []
            for target,source in mapping.items():
                value = values.get(source)
                if target in ('lat','lon'):
                    maximum = 90 if target=='lat' else 180
                    valid = type(value) in (int,float) and -maximum <= value <= maximum
                else: valid = type(value) is str and bool(value.strip())
                result[target] = value if valid else None
                if not valid: omissions.append(target)
            result.update(status='observed',omitted_fields=omissions)
        except (ValueError,UnicodeError,RecursionError) as error:
            result.update(status='invalid',reason=type(error).__name__)
        return result

    def _geolocate_ipapi(self, ip):
        _require_active(); return self._provider('ip-api',ip)

    def _geolocate_ipify(self, ip):
        _require_active(); return self._provider('ipify',ip)

    def geolocate_ip(self, ip):
        _require_active(); canonical = str(self._literal(ip)); now = time.monotonic()
        with self._cache_lock:
            cached = self.geolocation_cache.get(canonical)
            if cached is not None:
                if now < cached[0]:
                    value = copy.deepcopy(cached[1]); value['cache'] = {'hit':True,'scope':'This instance, at most 300 seconds'}
                    return value
                self._cache_bytes -= cached[2]; del self.geolocation_cache[canonical]
        attempts = []
        for method in (self._geolocate_ipapi,self._geolocate_ipify):
            value = method(ip); attempts.append(value)
            if value['status']=='observed':
                value = {**value,'attempts':copy.deepcopy(attempts),'cache':{'hit':False}}
                size = sum(len(chunk) for chunk in _json_chunks(value,16*1024**2))
                with self._cache_lock:
                    prior = self.geolocation_cache.pop(canonical,None)
                    if prior: self._cache_bytes -= prior[2]
                    self.geolocation_cache[canonical] = (time.monotonic()+300,copy.deepcopy(value),size)
                    self._cache_bytes += size
                    while len(self.geolocation_cache)>256 or self._cache_bytes > 16*1024**2:
                        self._cache_bytes -= self.geolocation_cache.popitem(last=False)[1][2]
                return value
        return {'status':'unavailable','ip':ip,'verified':False,'attempts':attempts,
                'reason':'No complete IP-bound provider observation; no default geography invented'}

    def whois_lookup(self, ip):
        _require_active(); self._literal(ip)
        return {'status':'unavailable','ip':ip,'verified':False,
                'reason':'Domain WHOIS does not establish IP allocation; validated IP RDAP collection is unavailable'}

    def analyze_risk_indicators(self, analysis_result):
        _require_active()
        raise NotImplementedError('No validated Sentinel IP risk model; missing PTR/provider data are not suspiciousness')

    def correlate_ips(self, victim_ips, known_attacker_ranges=None):
        _require_active()
        if type(victim_ips) is not list or len(victim_ips)>1000 or any(type(value) is not str or len(value)>128 for value in victim_ips):
            raise ValueError('At most 1000 textual IP observations required')
        if known_attacker_ranges is not None and (type(known_attacker_ranges) is not list or
                len(known_attacker_ranges)>256 or any(type(value) is not str or len(value)>64 for value in known_attacker_ranges)):
            raise ValueError('At most 256 textual supplied ranges required')
        ranges = [(value,ipaddress.ip_network(value,strict=False)) for value in (known_attacker_ranges or [])]
        groups, invalid, membership = {},[],[]
        for index,value in enumerate(victim_ips):
            try: info = self.get_network_info(value); address = self._literal(value)
            except ValueError: invalid.append(index); continue
            group = groups.setdefault(info['network'],[])
            if str(address) not in group: group.append(str(address))
            matches = [raw for raw,network in ranges if address.version==network.version and address in network]
            if matches: membership.append({'source_index':index,'supplied_ranges':matches,'verified':False})
        result = {'schema_version':2,'source_ips':list(victim_ips),'unusable_indices':invalid,
            'common_networks':{key:value for key,value in groups.items() if len(value)>1},
            'ip_clusters':groups,'geographic_clusters':{},'temporal_patterns':{},'potential_attacker_ranges':[],
            'supplied_range_membership':membership,'verified':False,'identity':'unavailable',
            'scope':'Unique address membership in assumed IPv4 /24 or IPv6 /64 groups; not people, allocated networks or attackers'}
        for _ in _json_chunks(result,32*1024**2): pass
        return result

    def batch_analyze_ips(self, ips, max_workers=5):
        _require_active(); native_integer(max_workers,'max_workers',64)
        if type(ips) is not list or len(ips)>1000: raise ValueError('At most 1000 IP literals required')
        for value in ips: self._literal(value)
        values = list(dict.fromkeys(ips))
        results = {}; size = 2
        with ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix='paw-sentinel-ip') as executor:
            pending = {}; source = iter(values)
            try:
                while True:
                    while len(pending) < max_workers:
                        value = next(source,None)
                        if value is None: break
                        pending[executor.submit(self.analyze_ip,value)] = value
                    if not pending: break
                    completed,_ = wait(pending,return_when=FIRST_COMPLETED)
                    for future in completed:
                        key = pending.pop(future); value = future.result()
                        size += sum(len(chunk) for chunk in _json_chunks({key:value},32*1024**2))
                        if size > 32*1024**2: raise ValueError('Sentinel IP batch output byte limit exceeded')
                        results[key] = value
            finally:
                for future in pending: future.cancel()
        return {key:results[key] for key in values}
