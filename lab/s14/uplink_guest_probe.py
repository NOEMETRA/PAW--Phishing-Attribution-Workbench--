"""Trusted guest probe: fixed owned benchmark address only, never live transport."""
import hashlib
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import tty

LOCK=threading.Lock()
STATE={'bytes':0,'last_byte':None,'eof':False,'running':False}
STOP=threading.Event()
THREAD=None

def connect():
    raw=socket.create_connection(('198.18.43.10',443),timeout=1)
    context=ssl.create_default_context(cafile='/etc/paw-uplink-ca.pem')
    client=context.wrap_socket(raw,server_hostname='allow.fixture.invalid')
    if client.getpeername()[0]!='198.18.43.10':raise ValueError('peer_binding')
    client.sendall(b'GET /get HTTP/1.0\r\nHost: allow.fixture.invalid\r\n\r\n')
    return client

def fetch():
    try:
        with connect() as client:
            response=http.client.HTTPResponse(client);response.begin();data=response.read(8193)
            if len(data)>8192:raise ValueError('response_budget')
            return {'status':'completed','http_status':response.status,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'peer':'198.18.43.10','tls_hostname':'allow.fixture.invalid','tls_verified':True}
    except Exception as error:return {'status':'unavailable','reason':type(error).__name__}

def stream():
    try:
        with connect() as client:
            client.settimeout(.2)
            with LOCK:STATE['running']=True
            deadline=time.monotonic()+12
            while not STOP.is_set() and time.monotonic()<deadline:
                try:data=client.recv(1024)
                except socket.timeout:continue
                if not data:
                    with LOCK:STATE['eof']=True
                    break
                with LOCK:
                    STATE['bytes']+=len(data);STATE['last_byte']=time.monotonic()
                    if STATE['bytes']>8192:raise ValueError('stream_bytes')
    except Exception as error:
        with LOCK:STATE['error']=type(error).__name__
    finally:
        with LOCK:STATE['running']=False

def stop():
    STOP.set()
    if THREAD:THREAD.join(timeout=2)

def dispatch(command):
    global THREAD
    op=command['op']
    if op=='state':
        with LOCK:value=dict(STATE)
        return {**value,'addresses':json.loads(subprocess.check_output(['/usr/sbin/ip','-j','address'])),
                'routes':json.loads(subprocess.check_output(['/usr/sbin/ip','-j','route']))}
    if op=='fetch':return fetch()
    if op=='stream':
        stop();STOP.clear()
        with LOCK:STATE.clear();STATE.update({'bytes':0,'last_byte':None,'eof':False,'running':False})
        THREAD=threading.Thread(target=stream,daemon=True);THREAD.start();return {'started':True}
    if op=='stop':stop();return {'stopped':not THREAD or not THREAD.is_alive()}
    raise ValueError('Only fixed owned fixture operations')

def emit(value):
    data=('PAW14 '+json.dumps(value)+'\n').encode();offset=0
    while offset<len(data):offset+=os.write(1,data[offset:])

def main():
    tty.setraw(0);emit({'ready':True,'mode':'owned-fixture-only'})
    while True:
        raw=sys.stdin.buffer.readline(4097)
        if not raw:return
        if len(raw)>4096:raise ValueError('frame_limit')
        value=json.loads(raw)
        try:result={'id':value['id'],'ok':True,'data':dispatch(value)}
        except Exception as error:result={'id':value['id'],'ok':False,'error':str(error)}
        emit(result)

if __name__=='__main__':main()
