"""oauth2/jwt.py -- unverified decoding of a compact JWS token.

Jwt.decode must return None on any malformed input and never raise, since
the tool decodes and displays tokens it never trusts.
"""

import base64
import json

from oauthenticator.oauth2.jwt import Jwt


def _segment(payload):
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()


def test_decode_returns_header_payload_and_raw_signature(token_signer):
    token = token_signer.sign({'sub': 'user-1', 'iss': 'https://issuer.test'})

    decoded = Jwt.decode(token)

    assert decoded['payload']['sub'] == 'user-1'
    assert decoded['header']['alg'] == 'RS256'
    assert decoded['signature'] == token.split('.')[2]


def test_decode_returns_none_for_wrong_segment_count():
    assert Jwt.decode('only-one-segment') is None
    assert Jwt.decode('two.segments') is None
    assert Jwt.decode('a.b.c.d') is None
    assert Jwt.decode('') is None


def test_decode_returns_none_for_bad_base64():
    # a segment whose data-character count is 1 mod 4 can never be fixed by
    # padding -- binascii rejects it regardless, unlike the other three
    # remainders exercised below.
    header = _segment({'alg': 'none'})
    broken_payload = 'a'

    assert Jwt.decode(f'{header}.{broken_payload}.sig') is None


def test_decode_returns_none_for_non_json_payload():
    header = _segment({'alg': 'none'})
    non_json_payload = base64.urlsafe_b64encode(b'not json at all').rstrip(b'=').decode()

    assert Jwt.decode(f'{header}.{non_json_payload}.sig') is None


def test_decode_handles_every_base64_padding_remainder():
    # segment lengths land on remainder 0, 2 or 3 depending on payload size;
    # remainder 1 never occurs for validly encoded base64 (see the bad-
    # base64 test above), so only these three are reachable with real data.
    payloads = [{'a': ''}, {'a': 'x'}, {'a': 'xx'}]

    for payload in payloads:
        segment = _segment(payload)
        assert len(segment) % 4 in (0, 2, 3)

        token = f'{segment}.{segment}.sig'
        decoded = Jwt.decode(token)

        assert decoded['payload'] == payload
