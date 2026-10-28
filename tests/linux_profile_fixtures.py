"""Owned ELF fixture bytes; no compiler, loader or sample execution."""
import struct


def executable(interpreter=None, kind=2):
    name = b'' if interpreter is None else interpreter.encode('ascii')+b'\0'
    count = 1+bool(name); offset = 64+count*56
    # Harmless exit(0) machine-code DATA. Tests never invoke this executable.
    code = b'\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05'
    size = offset+len(name)+len(code)
    header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01'+bytes(9), kind,
        62, 1, 0x400000+offset+len(name), 64, 0, 0, 64, 56, count, 0, 0, 0)
    load = struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0, size, size, 4096)
    interp = b'' if not name else struct.pack('<IIQQQQQQ', 3, 4, offset, 0, 0, len(name), len(name), 1)
    return header+interp+load+name+code


def changed(raw, offset, fmt, value):
    result = bytearray(raw); struct.pack_into(fmt, result, offset, value); return bytes(result)
