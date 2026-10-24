"""Synthetic WAN HTTP/TLS/DNS only; no forwarding or upstream resolver."""
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys
import threading
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from gw_admission import question,dns_response

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--directory',type=Path,required=True);args=parser.parse_args()
    root=args.directory;lock=threading.Lock();counts={}
    def log(event,**data):
        with lock,(root/'wan.jsonl').open('a') as stream:
            stream.write(json.dumps({'utc':time.time(),'event':event,**data})+'\n')
    config=json.loads((root/'fixture.json').read_text())
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            log('http',path=self.path,host=self.headers.get('Host'),peer=self.client_address[0],local=self.connection.getsockname()[0])
            if self.path=='/redirect-ok':
                self.send_response(302);self.send_header('Location','http://allow.fixture.invalid:18080/ok');self.end_headers();return
            if self.path=='/redirect-private':
                self.send_response(302);self.send_header('Location','http://private.fixture.invalid:18080/forbidden');self.end_headers();return
            if self.path=='/rebind':
                self.send_response(302);self.send_header('Location','http://rebind.fixture.invalid:18080/second');self.end_headers();return
            if self.path=='/loop':
                self.send_response(302);self.send_header('Location','/loop');self.end_headers();return
            self.send_response(200);self.end_headers()
            try:
                if self.path=='/slow':
                    log('stream_start')
                    for _ in range(300):self.wfile.write(b'owned heartbeat\n');self.wfile.flush();time.sleep(.1)
                else:self.wfile.write(b'x'*20000 if self.path=='/oversize' else b'OWNED-SYNTHETIC-WAN\n')
            except (OSError,ssl.SSLError):pass
    servers=[]
    for port in [18080,8443]:
        server=http.server.ThreadingHTTPServer(('0.0.0.0',port),Handler);server.daemon_threads=True
        if port==8443:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'server.pem',root/'server.key');server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
    def resolver():
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
            dns.bind(('198.18.40.10',5353))
            while True:
                data,peer=dns.recvfrom(513)
                try:
                    _,_,name,kind,_=question(data)
                    with lock:counts[name]=counts.get(name,0)+1;seen=counts[name]
                    values=['198.18.40.10']
                    if name.startswith('private.') or name.startswith('rebind.') and seen>1:values=[config['host_ip']]
                    elif name.startswith('loopback.'):values=['127.0.0.1']
                    elif name.startswith('metadata.'):values=['169.254.169.254']
                    elif name.startswith('mixed.'):values=['198.18.40.10','198.18.40.11']
                    answer=dns_response(data,values)
                    if name.startswith('badwire.'):answer=b'\0\0'+answer[2:]
                    log('dns',name=name,values=values,query_count=seen)
                    dns.sendto(answer,peer)
                except Exception as error:log('dns_error',reason=type(error).__name__)
    threading.Thread(target=resolver,daemon=True).start()
    (root/'wan-ready.json').write_text(json.dumps({'pid':os.getpid()}))
    while True:time.sleep(1)

if __name__=='__main__':main()
