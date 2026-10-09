"""Concurrency contracts for the real queue, no replacement analysis worker."""
import asyncio
from pathlib import Path
import tempfile
import time
import unittest
from paw.web import api

class GuiQueueContracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.previous=(api.JOBS_DIR,api._workers,api.analysis_queue,api._cancel_events)
        api.JOBS_DIR=Path(self.temp.name)
        api._workers=asyncio.Semaphore(1)
        api.analysis_queue={}
        api._cancel_events={}

    async def asyncTearDown(self):
        api.JOBS_DIR,api._workers,api.analysis_queue,api._cancel_events=self.previous
        self.temp.cleanup()

    def queued(self,identifier):
        api.analysis_queue[identifier]={'status':'queued','queued_monotonic':time.monotonic()}
        api._cancel_events[identifier]=asyncio.Event()

    async def consume(self,identifier):
        async with api.job_slot(identifier,api.RuntimeOptions(wall_seconds=10)) as acquired:
            return acquired

    async def test_queued_cancel_releases_admission_before_worker_finishes(self):
        await api._workers.acquire()
        identifier='analysis_cancelled'
        self.queued(identifier)
        task=asyncio.create_task(self.consume(identifier))
        await asyncio.sleep(.02)
        api._cancel_events[identifier].set()
        self.assertFalse(await asyncio.wait_for(task,1))
        self.assertNotIn(identifier,api._cancel_events)
        self.assertNotIn(identifier,api.analysis_queue)
        self.assertTrue(api._workers.locked())
        api._workers.release()

    async def test_cancel_and_slot_release_race_does_not_leak_a_permit(self):
        await api._workers.acquire()
        identifier='analysis_race'
        self.queued(identifier)
        task=asyncio.create_task(self.consume(identifier))
        await asyncio.sleep(.02)
        api._cancel_events[identifier].set()
        api._workers.release()
        self.assertFalse(await asyncio.wait_for(task,1))
        await asyncio.wait_for(api._workers.acquire(),.5)
        self.assertTrue(api._workers.locked())
        api._workers.release()

    async def test_worker_slot_remains_exclusive_until_scope_exits(self):
        identifier='analysis_exclusive'
        self.queued(identifier)
        async with api.job_slot(identifier,api.RuntimeOptions()) as acquired:
            self.assertTrue(acquired)
            self.assertTrue(api._workers.locked())
        self.assertFalse(api._workers.locked())

if __name__=='__main__':unittest.main()
