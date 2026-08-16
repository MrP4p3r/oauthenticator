"""What the CLI prints before the callback arrives: endpoints and the authorization URL.

Output modes
    By default nothing but the endpoints and the authorization URL reaches
    stdout and the browser is the interface. The URL is printed whether or
    not the browser opens, so it can be copied to another machine or
    reopened after the tab is lost.
"""

import webbrowser


def print_endpoints(config):
    print('authorization_endpoint:', config['authorization_endpoint'])
    print('token_endpoint:', config['token_endpoint'])


def open_browser(url, no_browser):
    print('\nauthorization URL:\n' + url)

    if no_browser or not webbrowser.open(url):
        print('\nopen it in a browser, waiting for the callback...')
    else:
        print('\nbrowser opened, waiting for the callback...')
