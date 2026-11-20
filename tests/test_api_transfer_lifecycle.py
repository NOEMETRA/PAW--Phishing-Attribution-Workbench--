import asyncio
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from starlette.requests import Request
from paw.web import api


class TransferLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_upload_envelope_rejected_before_body_read(self):
        for path, cap in [('/api/upload', 25), ('/api/sources/upload', 16)]:
            for headers, status in [
                ([], 411),
                ([(b'transfer-encoding', b'chunked')], 411),
                ([(b'content-length', str(cap * 1024**2 + 65537).encode())], 413),
            ]:
                request = Request(dict(type='http', method='POST', scheme='http',
                                       path=path, query_string=b'',
                                       headers=[(b'host', b'localhost'), *headers]))
                async def unexpected(request):
                    self.fail('Reached multipart parsing')
                response = await api.local_boundary(request, unexpected)
                self.assertEqual(response.status_code, status)

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
