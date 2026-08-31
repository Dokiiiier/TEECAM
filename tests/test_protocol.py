import io
import unittest

from cote3mon.protocol import (
    MAX_VALUE_BYTES,
    Operation,
    Request,
    Response,
    Status,
    recv_request,
    recv_response,
)


class ProtocolTests(unittest.TestCase):
    def test_request_round_trip(self):
        original = Request(123, Operation.PUT, b"key", b"value")
        decoded = recv_request(io.BytesIO(original.encode()))
        self.assertEqual(decoded, original)

    def test_response_round_trip(self):
        original = Response(123, Status.OK, b"value")
        decoded = recv_response(io.BytesIO(original.encode()))
        self.assertEqual(decoded, original)

    def test_rejects_over_limit_value(self):
        with self.assertRaises(ValueError):
            Request(1, Operation.PUT, b"key", b"x" * (MAX_VALUE_BYTES + 1)).encode()

    def test_get_rejects_value(self):
        with self.assertRaises(ValueError):
            Request(1, Operation.GET, b"key", b"unexpected").encode()


if __name__ == "__main__":
    unittest.main()

