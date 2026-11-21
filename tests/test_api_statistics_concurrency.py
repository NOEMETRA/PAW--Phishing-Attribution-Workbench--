"""Preserve fresh statistics while concurrent requests share a live scan."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from paw.web import api


class StatisticsConcurrency(unittest.IsolatedAsyncioTestCase):
    async def test_shared_scan_survives_one_request_cancellation_and_refreshes(self):
        entered = asyncio.Event()
        release = asyncio.Event()
        initial = {"total_cases": 2}
        updated = {"total_cases": 3}

        async def scan():
            entered.set()
            await release.wait()
            return initial

        with patch.object(api, "_collect_statistics", side_effect=scan) as collect:
            first = asyncio.create_task(api.get_statistics())
            try:
                await asyncio.wait_for(entered.wait(), 1)
                second = asyncio.create_task(api.get_statistics())
                third = asyncio.create_task(api.get_statistics())
                await asyncio.sleep(0)
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                release.set()
                results = await asyncio.wait_for(asyncio.gather(second, third), 1)
                self.assertEqual(results, [initial, initial])
                collect.assert_awaited_once()
                collect.side_effect = None
                collect.return_value = updated
                self.assertEqual(await api.get_statistics(), updated)
                self.assertEqual(collect.await_count, 2)
            finally:
                release.set()

    async def test_failed_scan_is_retried(self):
        result = {"total_cases": 1}
        scan = AsyncMock(side_effect=[OSError("fixture read failure"), result])
        with patch.object(api, "_collect_statistics", scan):
            with self.assertRaisesRegex(OSError, "fixture read failure"):
                await api.get_statistics()
            self.assertEqual(await api.get_statistics(), result)
        self.assertEqual(scan.await_count, 2)
