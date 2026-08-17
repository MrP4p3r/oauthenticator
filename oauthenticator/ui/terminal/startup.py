"""What the CLI prints before the callback arrives: endpoints and the authorization URL.

Output modes
    By default nothing but the endpoints and the authorization URL reaches
    stdout and the browser is the interface. The URL is printed whether or
    not the browser opens, so it can be copied to another machine or
    reopened after the tab is lost. It is printed through the console with
    markup and highlighting off, so a URL is never reinterpreted or
    recoloured -- only wrapping and truncation are already ruled out by the
    console's soft_wrap default.
"""

import webbrowser

from oauthenticator.ui.terminal.rendering import print_field


def print_endpoints(console, config):
    print_field(console, 'authorization_endpoint', config['authorization_endpoint'])
    print_field(console, 'token_endpoint', config['token_endpoint'])


def open_browser(console, url, no_browser):
    console.print()
    console.print('authorization URL:', style='bold')
    console.print(url, markup=False, highlight=False)

    if no_browser or not webbrowser.open(url):
        console.print('\nopen it in a browser, waiting for the callback...', style='dim')
    else:
        console.print('\nbrowser opened, waiting for the callback...', style='dim')
