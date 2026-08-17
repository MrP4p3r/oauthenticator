"""Fixtures for the fake OIDC provider.

The RSA keypair and its signer are built once per test session -- generating
a 2048-bit key is not free and every token in the suite can share one. The
provider itself is rebuilt for every test through `provider_factory`, so
issued codes, refresh tokens and injected failures never leak across tests.
"""

import pytest

from tests.plugins.oidc_provider.app import (
    CLIENT_ID, CLIENT_SECRET, ISSUER, FakeOidcProvider, build_http_client)
from tests.plugins.oidc_provider.keys import TokenSigner, generate_private_key_pem


@pytest.fixture(scope='session')
def token_signer():
    return TokenSigner(generate_private_key_pem())


@pytest.fixture
def provider_factory(token_signer):
    """Builds a FakeOidcProvider with test defaults, overridable per call."""

    def build(**overrides):
        options = {
            'issuer': ISSUER, 'signer': token_signer,
            'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET,
            **overrides,
        }

        return FakeOidcProvider(**options)

    return build


@pytest.fixture
def oidc_provider(provider_factory):
    return provider_factory()


@pytest.fixture
async def provider_http_client(oidc_provider):
    """An httpx.AsyncClient wired to the fake provider through ASGITransport -- no sockets."""
    async with build_http_client(oidc_provider) as client:
        yield client
