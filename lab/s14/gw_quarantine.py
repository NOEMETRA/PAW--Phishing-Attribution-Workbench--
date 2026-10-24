"""Host admission of small opaque extraction records, never guest paths/archives."""
import hashlib
import os
from pathlib import Path
import re

def validate_records(records):
    if type(records)is not list or len(records)>4:raise ValueError('record_count')
    result=[];names=set();total=0
    for record in records:
        if type(record)is not dict or set(record)!={'name','bytes_hex','sha256','scope'}:raise ValueError('record_shape')
        name=record['name'];encoded=record['bytes_hex']
        if type(name)is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',name) or name in {'.','..'} or name in names:
            raise ValueError('record_name')
        if type(encoded)is not str or len(encoded)>2048 or len(encoded)%2 or re.fullmatch(r'[0-9a-f]*',encoded)is None:
            raise ValueError('record_encoding_or_size')
        data=bytes.fromhex(encoded);total+=len(data)
        if total>4096:raise ValueError('aggregate_bytes')
        if hashlib.sha256(data).hexdigest()!=record['sha256']:raise ValueError('record_digest')
        names.add(name);result.append((name,data))
    return result

def publish(directory, records, stopped):
    if stopped is not True:raise ValueError('writers_not_confirmed_stopped')
    admitted=validate_records(records)
    directory=Path(directory);directory.mkdir(mode=0o700,exist_ok=False)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        manifest=[]
        for number,(name,data) in enumerate(admitted):
            output=f'artifact-{number:02d}.bin'
            target=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(target,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            manifest.append({'source_name':name,'stored_as':output,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'interpretation':'opaque, not rendered or expanded'})
        return manifest
    finally:os.close(fd)
