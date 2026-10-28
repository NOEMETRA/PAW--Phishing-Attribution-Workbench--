"""Finite Linux source admission metadata; never a loader or grant issuer.

All inspection is over bounded bytes. In particular ELF dependencies, interpreter
paths and sections are never opened, resolved, extracted or executed on the host.
An accepted header is not proof of guest loadability, harmlessness or isolation.
"""
from dataclasses import dataclass
import hashlib
import struct
from types import MappingProxyType


@dataclass(frozen=True)
class Profile:
    engine: str
    maximum_bytes: int
    media_type: str
    runtime: str


PROFILES = MappingProxyType({
    'shell': Profile('linux-posix-shell-offline-v1', 64*1024,
                     'text/x-shellscript', 'fixed guest /bin/dash; shebang does not select an interpreter'),
    'elf': Profile('linux-x86_64-elf-offline-v1', 1024**2,
                   'application/x-elf', 'Linux x86-64 LP64 executable/PIE in the guest only'),
})
ELF_INTERPRETERS = frozenset({'/lib64/ld-linux-x86-64.so.2', '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'})
ELF_PROGRAM_HEADERS = 128
ELF_LOAD_BYTES = 128*1024**2
USER_ADDRESS_END = 1 << 47


def require(value, reason):
    if not value: raise ValueError(reason)


def elf_metadata(raw):
    """Structural admission for executable ELF64 little-endian AMD64 only.

    Section tables/symbols and DT_NEEDED are intentionally uninterpreted. Guest
    loader errors and unavailable guest libraries remain execution outcomes.
    """
    require(type(raw) is bytes and 64 <= len(raw) <= PROFILES['elf'].maximum_bytes, 'elf_source_bytes')
    require(raw[:4] == b'\x7fELF' and raw[4:7] == b'\x02\x01\x01', 'elf_class_endian_version')
    require(raw[7] in {0, 3} and raw[8] == 0 and raw[9:16] == bytes(7), 'elf_abi_not_supported')
    (kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum,
     shsize, shnum, shstrings) = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    require(kind in {2, 3} and machine == 62 and version == 1 and flags == 0, 'elf_executable_amd64_required')
    require(ehsize == 64 and phsize == 56 and 1 <= phnum <= ELF_PROGRAM_HEADERS and
            64 <= phoff <= len(raw) and phnum*phsize <= len(raw)-phoff, 'elf_program_header_table')
    require(0 < entry < USER_ADDRESS_END, 'elf_executable_entry')
    loads = []; interpreter = None; mapped = 0; executable_entry = False
    for index in range(phnum):
        ptype, pflags, offset, address, physical, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', raw, phoff+index*phsize)
        if ptype == 0: continue  # PT_NULL members are undefined, not file/memory ranges.
        require(offset <= len(raw) and filesz <= len(raw)-offset, 'elf_segment_file_range')
        if ptype == 1:
            require(pflags & ~7 == 0 and filesz <= memsz and address < USER_ADDRESS_END and
                    memsz <= USER_ADDRESS_END-address, 'elf_load_segment')
            require(alignment in {0, 1} or (alignment <= 1 << 30 and alignment & (alignment-1) == 0 and
                    offset % alignment == address % alignment), 'elf_load_alignment')
            mapped += memsz; require(mapped <= ELF_LOAD_BYTES, 'elf_load_memory_budget')
            loads.append({'file_offset': offset, 'file_bytes': filesz, 'virtual_address': address,
                          'memory_bytes': memsz, 'flags': pflags, 'alignment': alignment})
            executable_entry |= bool(pflags & 1 and address <= entry < address+memsz)
        elif ptype == 3:
            require(interpreter is None and 1 < filesz <= 256, 'elf_single_interpreter')
            value = raw[offset:offset+filesz]
            require(value[-1:] == b'\0' and b'\0' not in value[:-1], 'elf_interpreter_string')
            try: interpreter = value[:-1].decode('ascii', 'strict')
            except UnicodeError as error: raise ValueError('elf_interpreter_ascii') from error
            require(interpreter in ELF_INTERPRETERS, 'elf_interpreter_not_supported')
    require(loads and executable_entry, 'elf_entry_not_executable_load')
    return {'format': 'ELF64-LSB-AMD64', 'kind': 'executable' if kind == 2 else 'position_independent',
            'entry': entry, 'program_headers': phnum, 'load_segments': loads,
            'mapped_load_bytes': mapped, 'interpreter': interpreter,
            'dependencies': 'not resolved on host; guest loader only',
            'section_tables': 'not interpreted; structural admission is not full ELF validation'}


def inspect_source(profile, raw):
    require(type(profile) is str and profile in PROFILES, 'linux_profile_not_supported')
    specification = PROFILES[profile]
    require(type(raw) is bytes and 0 < len(raw) <= specification.maximum_bytes, 'linux_profile_source_bytes')
    if profile == 'shell':
        try: raw.decode('utf-8', 'strict')
        except UnicodeError as error: raise ValueError('posix_shell_requires_utf8') from error
        require(b'\0' not in raw, 'posix_shell_nul')
        details = {'encoding': 'strict UTF-8 checked without rewriting bytes',
                   'syntax': 'not parsed on host; fixed guest dash decides POSIX-shell execution',
                   'shebang': 'preserved as source bytes, never used as a host or guest command selector'}
    else: details = elf_metadata(raw)
    return {'schema': 'paw-linux-source-admission-v1', 'profile': specification.engine,
            'source_bytes': len(raw), 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'maximum_source_bytes': specification.maximum_bytes, 'media_type': specification.media_type,
            'runtime': specification.runtime, 'details': details,
            'scope': 'bounded structural admission only; no source execution, authentication or safety verdict',
            'origin_verified': False, 'execution_authority': 'none'}
