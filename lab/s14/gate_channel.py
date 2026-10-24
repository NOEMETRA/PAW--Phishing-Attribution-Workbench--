"""Bounded hostile-synthetic response channel, separate from trusted fixture ABI."""
import json
import math
import os
import queue
import threading
import time

from benign_guest_validation import Serial


def validate_frame(value):
    count = 0
    def visit(item, depth):
        nonlocal count
        count += 1
        if depth > 8 or count > 512:
            raise ValueError('frame_complexity')
        if type(item) is float and not math.isfinite(item):
            raise ValueError('frame_nonfinite')
        if type(item) is dict:
            if any(type(k) is not str for k in item): raise ValueError('frame_key')
            for child in item.values(): visit(child, depth + 1)
        elif type(item) is list:
            for child in item: visit(child, depth + 1)
        elif type(item) not in {str, int, float, bool, type(None)}:
            raise ValueError('frame_type')
    if type(value) is not dict:
        raise ValueError('frame_object_required')
    visit(value, 0)
    return value


class GateChannel:
    def __init__(self, path, log):
        self.serial = Serial(path, log)
        self.responses = queue.Queue(maxsize=4)
        self.failure = None; self.done = False; self.expected = 0; self.awaiting_ready = True
        self.thread = threading.Thread(target=self.read, daemon=True); self.thread.start()

    def read(self):
        while not self.done:
            try:
                value = validate_frame(self.serial.message(.5))
                if self.awaiting_ready:
                    if value != {'ready': True, 'network_interfaces': ['lo']}:
                        raise ValueError('unexpected_readiness')
                    self.awaiting_ready = False
                elif (set(value) not in [{'id', 'ok', 'data'}, {'id', 'ok', 'error'}] or
                      type(value['id']) is not int or value['id'] != self.expected or type(value['ok']) is not bool):
                    raise ValueError('unexpected_response')
                self.responses.put_nowait(value)
            except TimeoutError:
                continue
            except Exception as error:
                self.failure = type(error).__name__ + ':' + str(error)
                return

    def take(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.failure: raise ValueError('guest_channel_failed:' + self.failure)
            try: return self.responses.get(timeout=min(.1, max(.001, deadline - time.monotonic())))
            except queue.Empty: pass
        raise TimeoutError('guest_channel_deadline')

    def ready(self, seconds=220):
        value = self.take(seconds)
        if value.get('ready') is not True: raise ValueError('missing_readiness')
        return value

    def call(self, operation, seconds=8, **values):
        self.expected += 1
        data = json.dumps({'id': self.expected, 'op': operation, **values}).encode() + b'\n'
        if len(data) > 4096: raise ValueError('command_budget')
        os.write(self.serial.fd, data)
        value = self.take(seconds)
        if value.get('id') != self.expected or value.get('ok') is not True: raise ValueError(str(value))
        return value['data']

    def close(self):
        self.done = True; self.thread.join(timeout=2); self.serial.close()
