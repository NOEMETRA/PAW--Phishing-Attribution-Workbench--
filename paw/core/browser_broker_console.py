"""Typed console transfer for the fixed owned no-NIC guest.

The accepted small-command GateChannel stays unchanged. Caller establishes the
same trusted owned VM descriptor and closes it after any protocol/write error.
"""
import base64
import hashlib
import json
import os
import re
import selectors
import time

MAX_COMMAND=60000

def require(value,reason):
    if not value:raise ValueError(reason)

def encode(identifier,value):
    require(type(identifier)is int and 1<=identifier<=4096 and type(value)is dict and
        type(value.get('nonce'))is str and re.fullmatch('[0-9a-f]{32}',value['nonce']) and
        type(value.get('seq'))is int and 0<=value['seq']<32,'owned_console_identity')
    kind=value.get('kind')
    if kind=='refusal':require(set(value)=={'kind','nonce','seq'},'owned_console_shape')
    elif kind=='begin':
        require(set(value)=={'kind','nonce','seq','bytes','sha256'}and type(value['bytes'])is int and
            0<value['bytes']<=65536 and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),
            'owned_console_metadata')
    else:
        require(set(value)=={'kind','nonce','seq','section','row'}and kind=='part'and
            value['section']in{'metadata','body'}and type(value['row'])is dict,'owned_console_transfer')
        row=value['row']
        require(row.get('nonce')==value['nonce']and type(row.get('seq'))is int and row['seq']==value['seq'],
            'owned_console_part_identity')
        if set(row)=={'nonce','seq','chunk','data_b64'}:
            require(type(row['chunk'])is int and 0<=row['chunk']<128 and type(row['data_b64'])is str and
                len(row['data_b64'])<=43692,'owned_console_chunk')
            raw=base64.b64decode(row['data_b64'],validate=True)
            require(0<len(raw)<=32768 and base64.b64encode(raw).decode('ascii')==row['data_b64'],'owned_console_chunk_bytes')
        else:
            require(set(row)=={'nonce','seq','done','chunks','body_bytes','body_sha256'} and row['done']is True and
                type(row['chunks'])is int and 0<=row['chunks']<=128 and type(row['body_bytes'])is int and
                0<=row['body_bytes']<=4*1024**2 and type(row['body_sha256'])is str and
                re.fullmatch('[0-9a-f]{64}',row['body_sha256']),'owned_console_end')
    raw=json.dumps({'id':identifier,'op':'network','value':value},separators=(',',':'),allow_nan=False).encode('ascii')+b'\n'
    require(len(raw)<MAX_COMMAND,'owned_console_budget')
    return raw

def write_all(fd,raw,deadline):
    """Descriptor is nonblocking; bounded writes preserve complete frames."""
    require(type(raw)is bytes and 0<len(raw)<MAX_COMMAND,'owned_console_write_budget')
    view=memoryview(raw)
    with selectors.DefaultSelector()as selected:
        selected.register(fd,selectors.EVENT_WRITE)
        while view:
            left=deadline-time.monotonic()
            require(left>0,'owned_console_write_deadline')
            if not selected.select(min(left,.1)):continue
            try:count=os.write(fd,view)
            except BlockingIOError:continue
            require(0<count<=len(view),'owned_console_short_write');view=view[count:]

def transfer(channel,value,seconds=2):
    """Only after the trusted controller establishes its owned VM descriptor."""
    identifier=channel.expected+1;raw=encode(identifier,value)
    require(type(seconds)in {int,float} and 0<seconds<=2,'owned_console_deadline')
    channel.expected=identifier;end=time.monotonic()+seconds
    write_all(channel.serial.fd,raw,end)
    result=channel.take(max(.001,end-time.monotonic()))
    require(result.get('id')==identifier and result.get('ok')is True,'owned_console_reply')
    return result['data']
