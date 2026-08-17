"""oauth2/discovery.py -- endpoint capability checks and required-endpoint failures."""

import pytest

from oauthenticator.oauth2 import discovery
from oauthenticator.oauth2.errors import DiscoveryError


def test_discovery_url_strips_a_trailing_slash_from_the_issuer():
    assert (discovery.discovery_url('https://issuer.test/') ==
           'https://issuer.test/.well-known/openid-configuration')
    assert (discovery.discovery_url('https://issuer.test') ==
           'https://issuer.test/.well-known/openid-configuration')


def test_validate_passes_when_both_required_endpoints_are_present():
    config = {'authorization_endpoint': 'https://issuer.test/authorize',
             'token_endpoint': 'https://issuer.test/token'}

    discovery.validate(config, 'https://issuer.test/.well-known/openid-configuration')


def test_validate_raises_when_authorization_endpoint_is_missing():
    config = {'token_endpoint': 'https://issuer.test/token'}

    with pytest.raises(DiscoveryError, match='authorization_endpoint'):
        discovery.validate(config, 'https://issuer.test/.well-known/openid-configuration')


def test_validate_raises_when_token_endpoint_is_missing():
    config = {'authorization_endpoint': 'https://issuer.test/authorize'}

    with pytest.raises(DiscoveryError, match='token_endpoint'):
        discovery.validate(config, 'https://issuer.test/.well-known/openid-configuration')


def test_supports_is_true_only_for_a_string_endpoint_url():
    assert discovery.supports({'userinfo_endpoint': 'https://issuer.test/userinfo'},
                              'userinfo_endpoint') is True
    assert discovery.supports({'userinfo_endpoint': None}, 'userinfo_endpoint') is False
    assert discovery.supports({}, 'userinfo_endpoint') is False


def test_endpoint_url_returns_the_url_when_present():
    config = {'userinfo_endpoint': 'https://issuer.test/userinfo'}

    assert discovery.endpoint_url(config, 'userinfo_endpoint') == 'https://issuer.test/userinfo'


def test_endpoint_url_raises_when_the_endpoint_is_absent():
    with pytest.raises(DiscoveryError, match='userinfo_endpoint'):
        discovery.endpoint_url({}, 'userinfo_endpoint')


def test_endpoint_url_raises_when_the_endpoint_is_not_a_string():
    with pytest.raises(DiscoveryError):
        discovery.endpoint_url({'userinfo_endpoint': 123}, 'userinfo_endpoint')
