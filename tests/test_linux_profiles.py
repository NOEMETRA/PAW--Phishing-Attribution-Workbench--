"""Owned ELF bytes are inspected, never loaded or executed on the host."""
import hashlib
import struct
import unittest

from paw.core import linux_profiles as profiles


from linux_profile_fixtures import executable, changed


class LinuxAdmission(unittest.TestCase):
    def test_shell_preserves_bom_crlf_and_shebang_without_selecting_that_program(self):
        raw = b'\xef\xbb\xbf#!/some/untrusted/program --argument\r\nprintf "owned"\r\n'
        result = profiles.inspect_source('shell', raw)
        self.assertEqual(result['source_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['source_bytes'], len(raw)); self.assertIn('/bin/dash', result['runtime'])
        self.assertEqual(result['execution_authority'], 'none'); self.assertFalse(result['origin_verified'])

    def test_shell_rejects_binary_nul_empty_and_oversize_without_lossy_decode(self):
        for raw in [b'', b'\xff', b'printf x\0', b'X'*(64*1024+1), bytearray(b'echo x'), '/tmp/source.sh']:
            with self.subTest(source_type=type(raw)), self.assertRaises(ValueError): profiles.inspect_source('shell', raw)

    def test_unknown_profile_never_becomes_a_host_interpreter_selector(self):
        for profile in ['python', 'bash', 'node', '/bin/sh', '../shell', True, None]:
            with self.subTest(profile=profile), self.assertRaises(ValueError): profiles.inspect_source(profile, b'echo owned')

    def test_profile_declarations_are_frozen(self):
        with self.assertRaises(TypeError): profiles.PROFILES['shell'] = profiles.PROFILES['elf']
        with self.assertRaises(AttributeError): profiles.PROFILES['shell'].maximum_bytes = 999999

    def test_static_executable_and_interpreted_pie_are_structurally_admitted(self):
        for path in [None, *sorted(profiles.ELF_INTERPRETERS)]:
            raw = executable(path, 3 if path else 2); result = profiles.inspect_source('elf', raw)
            self.assertEqual(result['details']['interpreter'], path)
            self.assertEqual(result['details']['format'], 'ELF64-LSB-AMD64')
            self.assertEqual(result['source_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result['execution_authority'], 'none'); self.assertIn('not resolved', result['details']['dependencies'])

    def test_wrong_magic_class_endian_architecture_abi_and_version_refuse(self):
        original = executable()
        for offset, fmt, value in [(0,'<I',0), (4,'B',1), (5,'B',2), (6,'B',2), (7,'B',9),
                                    (8,'B',1), (9,'B',1), (16,'<H',1), (18,'<H',183), (20,'<I',2), (48,'<I',1)]:
            with self.subTest(offset=offset), self.assertRaises(ValueError): profiles.inspect_source('elf', changed(original,offset,fmt,value))

    def test_program_header_ranges_sizes_and_count_are_bounded(self):
        original = executable()
        for offset, fmt, value in [(32,'<Q',0), (32,'<Q',2**64-1), (52,'<H',1), (54,'<H',1),
                                    (56,'<H',0), (56,'<H',129), (96,'<Q',len(original)+1), (104,'<Q',1)]:
            with self.subTest(offset=offset), self.assertRaises(ValueError): profiles.inspect_source('elf',changed(original,offset,fmt,value))
        for raw in [original[:63],original[:-1],original+b'X'*(1024**2),b'']:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError): profiles.inspect_source('elf',raw)

    def test_nonexecutable_unmapped_kernel_entry_and_memory_overflow_refuse(self):
        original = executable()
        for offset, fmt, value in [(24,'<Q',0), (24,'<Q',1), (24,'<Q',2**63), (68,'<I',4),
                                    (68,'<I',8), (80,'<Q',2**64-1), (104,'<Q',profiles.ELF_LOAD_BYTES+1),
                                    (112,'<Q',3), (112,'<Q',2**63)]:
            with self.subTest(offset=offset), self.assertRaises(ValueError): profiles.inspect_source('elf',changed(original,offset,fmt,value))

    def test_interpreter_is_only_metadata_and_outside_allowlist_refuses(self):
        for path in ['/bin/sh','/tmp/owned-loader','../../loader','/proc/self/fd/3']:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError,'elf_interpreter_not_supported'):
                profiles.inspect_source('elf',executable(path,3))
        raw=executable('/lib64/ld-linux-x86-64.so.2',3)
        # A nonterminated/interior-NUL interpreter never becomes a path lookup.
        start=64+2*56
        with self.assertRaises(ValueError): profiles.inspect_source('elf',changed(raw,start,'B',0))
        with self.assertRaises(ValueError): profiles.inspect_source('elf',changed(raw,start+len('/lib64/ld-linux-x86-64.so.2'),'B',ord('x')))

    def test_duplicate_interpreter_and_no_load_refuse(self):
        raw=executable('/lib64/ld-linux-x86-64.so.2',3)
        with self.assertRaises(ValueError): profiles.inspect_source('elf',changed(raw,120,'<I',3))
        with self.assertRaises(ValueError): profiles.inspect_source('elf',changed(executable(),64,'<I',0))

    def test_unused_program_header_members_are_not_interpreted_as_file_ranges(self):
        original = executable(); raw = bytearray(original[:120]+bytes(56)+original[120:])
        struct.pack_into('<H', raw, 56, 2)
        struct.pack_into('<Q', raw, 24, 0x400000+176)
        struct.pack_into('<Q', raw, 96, len(raw)); struct.pack_into('<Q', raw, 104, len(raw))
        # gABI PT_NULL leaves the remaining members undefined. This is data,
        # not a mapping; legitimate ignored entries must not become lookups.
        struct.pack_into('<IIQQQQQQ', raw, 120, 0, 0xffffffff, *([2**64-1]*6))
        result = profiles.inspect_source('elf',bytes(raw))
        self.assertEqual(result['details']['program_headers'],2)
        self.assertEqual(len(result['details']['load_segments']),1)


if __name__ == '__main__': unittest.main()
