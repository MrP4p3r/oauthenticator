"""Pure front-channel URL builders.

Each function takes provider metadata plus flow parameters and returns a
URL; neither function performs a request or touches provider state.
"""

import urllib.parse


def authorization_url(config, client_id, redirect_uri, scope, state, nonce, code_challenge):
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state,
        'nonce': nonce,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    }
    separator = '&' if '?' in config['authorization_endpoint'] else '?'

    return config['authorization_endpoint'] + separator + urllib.parse.urlencode(params)


def end_session_url(endpoint, client_id, id_token, post_logout_redirect):
    """RP-initiated logout redirect.

    Revocation kills tokens, not the login: the provider still recognises
    the browser and hands out a new grant without a prompt. Ending the
    session instead needs this front-channel redirect, carrying
    id_token_hint when available. post_logout_redirect is opt-in because
    providers reject it unless it is registered for the client.
    """
    params = {'client_id': client_id}

    if id_token is not None:
        params['id_token_hint'] = id_token
    if post_logout_redirect is not None:
        params['post_logout_redirect_uri'] = post_logout_redirect

    separator = '&' if '?' in endpoint else '?'

    return endpoint + separator + urllib.parse.urlencode(params)
