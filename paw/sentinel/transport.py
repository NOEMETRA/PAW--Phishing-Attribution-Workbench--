"""Bounded single-response HTTP observations; no redirects, rendering or identity claims."""
import hashlib
import math
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .contracts import _require_active
from ..core.network_policy import EgressDenied
from ..deobfuscate.url import http_url_status
from ..util.timeutil import utc_now_iso


def positive_number(value, name, maximum=3600):
    if type(value) not in (int,float) or not 0 < value <= maximum or not math.isfinite(value):
        raise ValueError(f'{name} requires a positive finite native number <= {maximum}')
    return value


def native_integer(value, name, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError(f'{name} requires a positive native integer <= {maximum}')
    return value


def _source_url(value, secret_keys):
    parsed = urlsplit(value)
    netloc = parsed.netloc.rsplit('@',1)[-1]
    query = urlencode([(key,'[redacted]' if key.casefold() in secret_keys else item)
                       for key,item in parse_qsl(parsed.query,keep_blank_values=True)])
    return urlunsplit((parsed.scheme,netloc,parsed.path,query,parsed.fragment)) if secret_keys or '@' in parsed.netloc else value


def fetch_http(url, *, timeout=30, max_bytes=2*1024**2, proxies=None, params=None, stop_event=None):
    _require_active()
    if type(url) is not str or http_url_status(url)[0] != 'completed':
        raise ValueError('Sentinel collection requires a complete absolute HTTP(S) URL')
    positive_number(timeout,'timeout',300); native_integer(max_bytes,'max_bytes',8*1024**2)
    if params is not None and type(params) is not dict: raise ValueError('Native request parameter mapping required')
    if proxies is not None and type(proxies) is not dict: raise ValueError('Native proxy mapping required')
    if params is not None and (len(params)>64 or any(type(key) is not str or type(value) is not str or
            len(key)>128 or len(value)>4096 for key,value in params.items())):
        raise ValueError('Bounded native textual request parameters required')
    if proxies is not None and any(key not in ('http','https') or type(value) is not str or
            http_url_status(value)[0]!='completed' for key,value in proxies.items()):
        raise ValueError('Explicit HTTP(S) proxy endpoints required')
    secrets = {'apikey'}
    started = time.monotonic()
    result = {'status':'error','requested_url':_source_url(url,secrets),'response_url':None,
        'observed_at':utc_now_iso(),'http_status':None,'body':b'','body_status':'not_evaluated',
        'content_sha256':None,'verified':False,'elapsed_seconds':None,
        'scope':'One unverified HTTP response; redirects, browser use and campaign liveness not evaluated',
        'redirects_followed':False,'error':None,'retained_bytes':0,
        'retained_sha256':hashlib.sha256(b'').hexdigest(),'body_representation':'HTTP entity bytes, without content decoding',
        'transport_route':'explicit_proxy' if proxies else 'direct; environment proxies ignored',
        'response_headers':{'status':'not_evaluated','entries':[],
                            'scope':'Library-decoded response fields; not raw HTTP wire bytes','max_characters':16384}}
    chunks = []
    try:
        if stop_event is not None and stop_event.is_set():
            result.update(error='Collection canceled',elapsed_seconds=time.monotonic()-started)
            return result
        import requests
        with requests.Session() as session:
            session.trust_env = False
            with session.get(url,params=params,proxies=proxies,timeout=timeout,stream=True,
                             allow_redirects=False,headers={'User-Agent':'PAW-Sentinel/1.0','Accept-Encoding':'identity'}) as response:
                result.update(http_status=response.status_code,
                              response_url=_source_url(response.url,secrets),
                              content_encoding=response.headers.get('Content-Encoding','identity')[:4096])
                headers = result['response_headers']; remaining = headers['max_characters']
                headers['status'] = 'completed'
                for name,value in response.raw.headers.iteritems():
                    if len(name)+len(value)>remaining:
                        headers['status'] = 'partial'; break
                    headers['entries'].append([name,value]); remaining -= len(name)+len(value)
                consumed = 0
                result['body_status'] = 'completed'
                while True:
                    if stop_event is not None and stop_event.is_set():
                        result.update(body_status='partial',error='Collection canceled'); break
                    if time.monotonic()-started > timeout:
                        result.update(body_status='partial',error='Response collection deadline exceeded'); break
                    # read1 returns currently available raw bytes: a slow drip
                    # cannot postpone our deadline until an 8192-byte fill.
                    read1 = getattr(response.raw,'read1',None)
                    chunk = (read1(8192,decode_content=False) if read1 is not None
                             else response.raw.read(1,decode_content=False))
                    if not chunk: break
                    retained = chunk[:max_bytes-consumed+1]
                    chunks.append(retained); consumed += len(retained)
                    if consumed > max_bytes:
                        result.update(body_status='partial',error='Response byte limit exceeded'); break
                result['body'] = b''.join(chunks)
                if result['body_status'] == 'completed':
                    result['content_sha256'] = hashlib.sha256(result['body']).hexdigest()
                result['status'] = 'observed'
    except EgressDenied:
        raise
    except ImportError:
        result.update(status='unavailable',error='Optional HTTP dependency unavailable')
    except Exception as error:
        # Do not leak credential-bearing request exception strings or mistake
        # transport/dependency failures for a remote campaign going down.
        result.update(status='error',error=type(error).__name__)
        if result['http_status'] is not None: result['body_status'] = 'partial'
    result['body'] = b''.join(chunks)
    result['retained_bytes'] = len(result['body'])
    result['retained_sha256'] = hashlib.sha256(result['body']).hexdigest()
    result['elapsed_seconds'] = time.monotonic()-started
    return result
