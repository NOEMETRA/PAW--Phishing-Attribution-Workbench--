"""Bounded offline HTTP fetch broker and DNS service inside the gateway VM."""
import argparse
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
import urllib.parse

sys.path.insert(0,str(Path(__file__).resolve().parent))
from gw_admission import Refused, admit_addresses, admit_url, dns_lookup, dns_response, question, require, strict_json

CONFIG=json.loads(Path('/etc/paw-gateway.json').read_text())
STATE=Path('/var/lib/paw-s14')
LOCK=threading.Lock()
COUNT=0
BYTES=0

def log(event, **values):
    with LOCK, (STATE/('dns.jsonl' if '--dns' in sys.argv else 'broker.jsonl')).open('a') as stream:
        stream.write(json.dumps({'time_utc':time.time(),'monotonic':time.monotonic(),'event':event,**values})+'\n')

def active():
    value=json.loads(Path('/run/paw-s14-active.json').read_text())
    require(time.monotonic()<value['expiry'],'expired')

def charge(size=0):
    global COUNT,BYTES
    active()
    with LOCK:
        require(COUNT<32 and BYTES+size<=32768,'budget')
        COUNT+=1;BYTES+=size

def resolve(host):
    values=dns_lookup(host)
    address=admit_addresses(values,CONFIG['mode'])
    log('resolution',host=host,addresses=values,admitted=address)
    return address

def fetch(url):
    global BYTES
    hops=[]
    for redirect in range(4):
        charge()
        target=admit_url(url,CONFIG['hosts'])
        address=resolve(target['host'])
        client=socket.create_connection((address,target['port']),timeout=1)
        try:
            peer=client.getpeername()[0]
            require(peer==address,'peer_binding')
            tls=False
            if target['scheme']=='https':
                context=ssl.create_default_context(cafile='/etc/paw-fixture-ca.pem')
                client=context.wrap_socket(client,server_hostname=target['host']);tls=True
            log('connect',host=target['host'],admitted_ip=address,peer_ip=peer,port=target['port'],tls_verified=tls)
            request=f"GET {target['path']} HTTP/1.1\r\nHost: {target['host']}:{target['port']}\r\nConnection: close\r\n\r\n".encode('ascii')
            client.sendall(request)
            response=http.client.HTTPResponse(client);response.begin()
            locations=response.headers.get_all('Location',[])
            require(len(locations)<=1,'ambiguous_location')
            hop={'url':target['url'],'status':response.status,'peer':peer,'tls_verified':tls}
            hops.append(hop)
            if response.status in {301,302,303,307,308}:
                require(locations and redirect<3,'redirect_limit_or_missing_location')
                url=urllib.parse.urljoin(target['url'],locations[0]);continue
            body=bytearray()
            while True:
                active()
                data=response.read1(1024)
                if not data:break
                require(len(body)+len(data)<=8192,'response_bytes')
                with LOCK:
                    require(BYTES+len(data)<=32768,'aggregate_bytes');BYTES+=len(data)
                body.extend(data)
            log('completed',hops=hops,bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            return {'status':'completed','hops':hops,'body_hex':bytes(body).hex(),'bytes':len(body)}
        finally:client.close()
    raise Refused('redirect_limit')

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def log_message(self,*args):pass
    def do_CONNECT(self):self.send_error(405)
    def do_GET(self):self.send_error(405)
    def do_POST(self):
        result={}
        try:
            require(self.path=='/fetch','api_path')
            require(self.headers.get('Authorization')=='Bearer '+CONFIG['token'],'job_token')
            lengths=self.headers.get_all('Content-Length',[])
            require(len(lengths)==1 and lengths[0].isdigit() and 0<int(lengths[0])<=4096,'request_bytes')
            require(not self.headers.get('Transfer-Encoding'),'request_transfer_encoding')
            self.connection.settimeout(2)
            value=strict_json(self.rfile.read(int(lengths[0])))
            require(type(value)is dict and set(value)=={'job_id','url'} and value['job_id']==CONFIG['job_id'],'job_identity')
            result=fetch(value['url'])
        except Refused as error:result={'status':'refused','reason':str(error)}
        except Exception as error:result={'status':'unavailable','reason':type(error).__name__}
        log('result',**result)
        data=json.dumps(result).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except OSError:pass

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--dns',action='store_true');args=parser.parse_args()
    require(CONFIG['mode']=='offline-fixture','live_transport_unavailable')
    if args.dns:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
            server.bind(('192.0.2.1',5353))
            for _ in range(16):
                data,peer=server.recvfrom(513)
                try:
                    active();_,_,name,kind,_=question(data)
                    require(name in CONFIG['hosts'] and kind==1,'dns_name_or_type_not_admitted')
                    address=resolve(name);answer=dns_response(data,[address])
                except Exception as error:
                    log('dns_refused',reason=type(error).__name__)
                    try:answer=dns_response(data,refused=True)
                    except Exception:continue
                server.sendto(answer,peer)
    else:
        server=http.server.ThreadingHTTPServer(('192.0.2.1',3128),Handler)
        server.daemon_threads=True
        server.serve_forever()

if __name__=='__main__':main()
