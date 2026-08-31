import json
import os
from pathlib import Path
import socket
import tempfile
import unittest

from cote3mon.mock_gateway import MockGateway
from cote3mon.protocol import Operation, Request, Status, call
from cote3mon.workload import _malformed


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
class GatewayIntegrationTests(unittest.TestCase):
    def test_put_get_delete_and_malformed_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = str(Path(directory) / "gateway.sock")
            telemetry = Path(directory) / "events.jsonl"
            with MockGateway(socket_path, telemetry, "run-1", "steady", False):
                self.assertEqual(call(socket_path, Request(1, Operation.PUT, b"key", b"value")).status, Status.OK)
                response = call(socket_path, Request(2, Operation.GET, b"key"))
                self.assertEqual(response.status, Status.OK)
                self.assertEqual(response.value, b"value")
                self.assertEqual(call(socket_path, Request(3, Operation.DELETE, b"key")).status, Status.OK)
                self.assertEqual(call(socket_path, Request(4, Operation.GET, b"key")).status, Status.NOT_FOUND)
                _malformed(socket_path, 5)
            events = [json.loads(line) for line in telemetry.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(events), 5)
            self.assertEqual(events[-1]["operation"], "REJECT")
            self.assertEqual(events[-1]["result"], "PROTOCOL_ERROR")
            self.assertTrue(events[0]["key_fingerprint"])
            self.assertTrue(events[0]["request_fingerprint"])
            self.assertNotIn("key", events[0])
            self.assertEqual(events[-1]["key_fingerprint"], "")
            self.assertEqual(events[-1]["request_fingerprint"], "")


if __name__ == "__main__":
    unittest.main()
