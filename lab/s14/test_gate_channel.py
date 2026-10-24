"""Malformed guest responses never become successful control evidence."""
import queue
import threading
import unittest
from types import SimpleNamespace
from gate_channel import GateChannel, validate_frame


class Frames(unittest.TestCase):
    def test_nonobjects_nonfinite_and_deep_frames_refuse(self):
        deep = 0
        for _ in range(10): deep = [deep]
        for value in [[], 'scalar', None, {'x': float('nan')}, {'x': deep}, {'x': [0] * 513}]:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError): validate_frame(value)

    def test_valid_bounded_data_retains_literal_content(self):
        value = {'id': 1, 'ok': True, 'data': {'literal': '<script>inert</script>', 'observed': 0}}
        self.assertIs(validate_frame(value), value)

    def test_hostile_frame_is_recorded_as_failure_without_thread_escape(self):
        for value in [[], {'id': True, 'ok': True, 'data': {}}, {'id': 9, 'ok': True, 'data': {}}]:
            channel = GateChannel.__new__(GateChannel)
            channel.serial = SimpleNamespace(message=lambda _: value)
            channel.done = False; channel.failure = None; channel.expected = 1; channel.awaiting_ready = False
            channel.responses = queue.Queue(maxsize=4)
            channel.read()
            self.assertIsNotNone(channel.failure)
            self.assertTrue(channel.responses.empty())
            with self.assertRaisesRegex(ValueError, 'guest_channel_failed'): channel.take(1)


if __name__ == '__main__': unittest.main()
