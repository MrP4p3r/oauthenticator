"""Exceptions raised by the oauth2 layer.

Kept deliberately small: callers across layer boundaries catch `OAuth2Error`
instead of the bare `RuntimeError` the original script raised, so a caller
never has to guess whether a `RuntimeError` came from the provider or from
somewhere else entirely.
"""


class OAuth2Error(Exception):
    """Base class for errors raised while talking to the provider."""


class DiscoveryError(OAuth2Error):
    """The discovery document lacks a required or requested endpoint."""


class ProviderRequestError(OAuth2Error):
    """A request to the provider failed at the transport or HTTP level."""
