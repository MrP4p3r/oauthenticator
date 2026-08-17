"""The fake OIDC issuer plugin, attached through `pytest_plugins` in tests/conftest.py.

Fixtures are defined in conftest.py and re-imported here so pytest finds
them at this package's top level, the shape `pytest_plugins` expects.
"""

from tests.plugins.oidc_provider.app import (
    CLIENT_ID, CLIENT_SECRET, ISSUER, FakeOidcProvider, build_http_client)
from tests.plugins.oidc_provider.conftest import (
    oidc_provider, provider_factory, provider_http_client, token_signer)
from tests.plugins.oidc_provider.keys import TokenSigner, generate_private_key_pem

__all__ = [
    'CLIENT_ID',
    'CLIENT_SECRET',
    'ISSUER',
    'FakeOidcProvider',
    'TokenSigner',
    'build_http_client',
    'generate_private_key_pem',
    'oidc_provider',
    'provider_factory',
    'provider_http_client',
    'token_signer',
]
