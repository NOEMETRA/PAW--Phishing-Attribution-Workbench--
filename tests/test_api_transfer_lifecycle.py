import asyncio
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from starlette import formparsers
from paw.web import api


async def upload(path, headers, messages, root_path=''):
    responses = []
    scope = {'type':'http', 'asgi':{'version':'3.0','spec_version':'2.4'},
             'method':'POST', 'scheme':'http', 'path':root_path+path, 'root_path':root_path, 'query_string':b'',
             'headers':[(b'host',b'localhost'), (b'content-type',b'multipart/form-data; boundary=abc'), *headers]}

    async def receive():
        return next(messages)

    async def send(message):
        responses.append(message)

    await api.app(scope, receive, send)
    return responses[0]['status']


class TransferLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_upload_envelope_rejected_before_body_read(self):
        for path, cap in [('/api/upload', 25), ('/api/sources/upload', 16)]:
            for headers, status in [
                ([], 411),
                ([(b'transfer-encoding', b'chunked')], 411),
                ([(b'content-length', b'5'), (b'content-length', b'6')], 400),
                ([(b'content-length', str(cap * 1024**2 + 65537).encode())], 413),
            ]:
                for root in ('', '/paw'):
                    self.assertEqual(await upload(path, headers, iter(()), root), status)

    async def test_upload_caps_actual_chunks_and_discards_spooled_files_on_mismatch(self):
        prefix = (b'--abc\r\nContent-Disposition: form-data; name="file"; filename="fixture.eml"'
                  b'\r\n\r\n' + b'x' * (1024**2 + 1))
        end = b'\r\n--abc--\r\n'
        for path, limit in api.UPLOAD_ENVELOPE_BYTES.items():
            for declared, tail, status in (
                (len(prefix), end, 400),
                (len(prefix) + len(end) + 1, end, 400),
                (limit, b'x' * (limit + 1 - len(prefix)), 413),
                (len(prefix) + len(end), None, 400),
                (len(prefix) + len(end), end, 200),
            ):
                with self.subTest(path=path, status=status, declared=declared), tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp)
                    spool = []
                    create_spool = formparsers.SpooledTemporaryFile

                    def track(*args, **kwargs):
                        file = create_spool(*args, **kwargs)
                        spool.append(file)
                        return file

                    def messages():
                        yield dict(type='http.request', body=prefix, more_body=True)
                        self.assertTrue(spool[0]._rolled)
                        if tail is not None:
                            yield dict(type='http.request', body=tail, more_body=False)
                        yield {'type':'http.disconnect'}

                    with patch.object(api, 'UPLOAD_DIR', directory), patch.object(formparsers, 'SpooledTemporaryFile', track):
                        headers = [(b'content-length', str(declared).encode())]
                        self.assertEqual(await upload(path, headers, messages()), status)
                    self.assertEqual(len(spool), 1)
                    self.assertTrue(spool[0].closed)
                    if status == 200:
                        saved = [item for item in directory.iterdir() if item.suffix != '.json']
                        self.assertEqual(len(saved), 1)
                        self.assertEqual(saved[0].read_bytes(), b'x' * (1024**2 + 1))
                    else:
                        self.assertFalse(list(directory.iterdir()))

    async def test_distinct_downloads_disconnect_and_crash_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / 'case-test'
            case.mkdir()
            (case / 'input.eml').write_bytes(b'Subject: fixture\r\n\r\nRecord')
            exports = root / 'exports'
            exports.mkdir()
            with patch.object(api, 'EXPORT_DIR', exports), patch.object(api, 'JOBS_DIR', root/'jobs'):
                first, second = await asyncio.gather(
                    asyncio.to_thread(api.prepare_download, case),
                    asyncio.to_thread(api.prepare_download, case))
                self.assertNotEqual(first.path, second.path)
                scope = dict(type='http', method='GET', headers=[], asgi={'spec_version': '2.4'})
                async def receive():
                    await asyncio.Event().wait()
                async def disconnect(message):
                    raise OSError('fixture disconnected')
                with self.assertRaises((OSError, RuntimeError)):
                    await first(scope, receive, disconnect)
                self.assertFalse(Path(first.path).exists())
                self.assertTrue(Path(second.path).exists())
                data = io.BytesIO()
                async def send(message):
                    data.write(message.get('body', b''))
                await second(scope, receive, send)
                with zipfile.ZipFile(data) as archive:
                    self.assertEqual(archive.read('input.eml'), (case/'input.eml').read_bytes())
                self.assertFalse(list(exports.iterdir()))
                stale = exports/'paw-download-abcd1234'
                stale.mkdir()
                (stale/'case.zip').write_bytes(b'incomplete')
                keep = exports/'analyst.zip'
                keep.write_bytes(b'preserve')
                async with api.lifespan(api.app):
                    self.assertFalse(stale.exists())
                    self.assertEqual(keep.read_bytes(), b'preserve')
