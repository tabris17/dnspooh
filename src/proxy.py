from urllib.parse import urlsplit
from ipaddress import ip_address


DEFAULT_HTTP_PROXY_PORT = 8080

DEFAULT_SOCKS5_PROXY_PORT = 1080

class Proxy:
    def __init__(self, url, hostname, port, host=None):
        self.url = url
        self.hostname = hostname
        self.port = port
        self.host = host

    def __repr__(self):
        return str(vars(self))


class HttpProxy(Proxy): pass


class Socks5Proxy(Proxy): pass


def parse_proxy(url):
    if not url:
        return None

    parsed_url = urlsplit(url)
    if parsed_url.path != '' and \
        parsed_url.path != '/' or \
        parsed_url.query != '' or \
        parsed_url.fragment != '':
        raise ValueError('Invalid proxy "{0}"'.format(url))

    try:
        host = ip_address(parsed_url.hostname)
    except ValueError:
        host = None

    if parsed_url.scheme == 'http':
        return HttpProxy(
            url, 
            parsed_url.hostname, 
            parsed_url.port if parsed_url.port \
                else DEFAULT_HTTP_PROXY_PORT,
            host
        )
    elif parsed_url.scheme == 'socks5':
        return Socks5Proxy(
            url, 
            parsed_url.hostname, 
            parsed_url.port if parsed_url.port \
                else DEFAULT_SOCKS5_PROXY_PORT,
            host
        )
    else:
        raise ValueError('Invalid proxy scheme "{0}" in "{1}"'.format(url, parsed_url.scheme))
