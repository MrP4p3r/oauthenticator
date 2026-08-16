"""Unverified decoding of a compact JWS token."""

import base64
import json


class Jwt:
    """Unverified decoding of a compact JWS token."""

    @staticmethod
    def decode(token):
        parts = token.split('.')
        if len(parts) != 3:
            return None

        try:
            header = Jwt._decode_segment(parts[0])
            payload = Jwt._decode_segment(parts[1])
        except ValueError:
            return None

        return {'header': header, 'payload': payload, 'signature': parts[2]}

    @staticmethod
    def _decode_segment(segment):
        padded = segment + '=' * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode()))
