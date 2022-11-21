import logging
from urllib.parse import urlsplit
from ipaddress import ip_address

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

VERSION = '0.1.0'

LISTEN_HOST = '0.0.0.0'

UPSTREAM_TIMEOUT = 1

CACHE_MAX_SIZE = 4096

CACHE_TTL = 3600

DEFAULT_DOT_PORT = 853

DEFAULT_DNS_PORT = 53

DEFAULT_HTTPS_PORT = 443

DEFAULT_HTTP_PROXY_PORT = 8080

DEFAULT_SOCKS5_PROXY_PORT = 1080

BUILTIN_UPSTREAMS = [
    {
        'name': 'google-1',
        'type': 'dns',
        'host': '8.8.8.8',
        'port': DEFAULT_DNS_PORT,
        'group': 'google',
    },
    {
        'name': 'google-2',
        'type': 'dns',
        'host': '8.8.4.4',
        'port': DEFAULT_DNS_PORT,
        'group': 'google',
    },
    {
        'name': 'alidns-1',
        'type': 'dns',
        'host': '223.6.6.6',
        'port': DEFAULT_DNS_PORT,
        'group': 'alidns',
    },
    {
        'name': 'alidns-2',
        'type': 'dns',
        'host': '223.5.5.5',
        'port': DEFAULT_DNS_PORT,
        'group': 'alidns',
    },
]

DEFAULT_CONFIG = {
    'debug': False,
    'host': LISTEN_HOST,
    'port': DEFAULT_DNS_PORT,
    'timeout': UPSTREAM_TIMEOUT,
    'upstreams': BUILTIN_UPSTREAMS,
    'proxy': None,
}


class Stats:
    pass


class Upstreams:
    def __init__(self):
        self._default = list()
        self._grouped = dict()


class Upstream:
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', '')
        self.proxy = kwargs.get('proxy')
        self.timeout = kwargs.get('timeout')
        self.group = kwargs.get('group')
        self.stats = Stats()

    def __repr__(self):
        return str(vars(self))

    def to_addr(self):
        return (self.host, self.port)


class DnsUpstream(Upstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.host = kwargs['host']
        self.port = kwargs.get('port', DEFAULT_DNS_PORT)


class HttpsUpstream(Upstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.url = kwargs['url']
        parsed_url = urlsplit(self.url)
        self.hostname = parsed_url.hostname
        try:
            ip_address(parsed_url.hostname)
            self.host = parsed_url.hostname
        except ValueError:
            self.host = None
        self.port = parsed_url.port if parsed_url.port else DEFAULT_HTTPS_PORT
        self.path = parsed_url.path


class TlsUpstream(Upstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hostname = kwargs['host']
        try:
            ip_address(self.hostname)
            self.host = self.hostname
        except ValueError:
            self.host = None
        self.port = kwargs.get('port', DEFAULT_DOT_PORT)


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


class ConfigInvalid(Exception):
    pass


def proxy_from_url(url):
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


def parse_upstream(server):
    if isinstance(server, dict):
        server_type = server.get('type', 'https' if 'url' in server else 'dns')
        if server_type == 'dns':
            upstream_class = DnsUpstream
        elif server_type == 'https':
            upstream_class = HttpsUpstream
        elif server_type == 'tls':
            upstream_class = TlsUpstream
        else:
            raise ConfigInvalid('Invalid upstream type')
        try:
            return upstream_class(**server)
        except KeyError as e:
            raise ConfigInvalid('Missing config key "{0}" in "{1}"'.format(e.args[0], server))
    elif not isinstance(server, str):
        raise TypeError('Parameter server must be dict or string')

    parsed_url = urlsplit(
        server if server.startswith('https://') \
            else '//' + server
    )

    if parsed_url.scheme == 'https':
        return HttpsUpstream(url=server)

    if parsed_url.path == '' and \
       parsed_url.query == '' and \
       parsed_url.fragment == '':
        if parsed_url.port == DEFAULT_DOT_PORT:
            return TlsUpstream(host=parsed_url.hostname, port=DEFAULT_DOT_PORT)
        else:
            return DnsUpstream(host=parsed_url.hostname, 
                               port=DEFAULT_DNS_PORT \
                                   if parsed_url.port is None \
                                   else parsed_url.port)

    raise ValueError('Invalid upstream format "{0}"'.format(server))


def load_from_file(file):
    with open(file, 'r') as stream:
        return yaml.load(stream, Loader=Loader)


def load_from_args(args):
    conf = dict()

    if args.debug is not None:
        conf['debug'] = args.debug

    if args.host is not None:
        conf['host'] = args.host

    if args.port is not None:
        conf['port'] = args.port

    if args.timeout is not None:
        conf['timeout'] = args.timeout

    if args.upstreams is not None:
        conf['upstreams'] = args.upstreams

    return conf


def merge_dict_recursive(original, addition):
    def _unique(l):
        unique_l = list()
        for _ in l:
            if _ not in unique_l:
                unique_l.append(_)
        return unique_l

    for k, v in addition.items():
        if k not in original:
            if v is not None:
                original[k] = v
        else:
            orig_v = original[k]
            if isinstance(orig_v, dict) and isinstance(v, dict):
                merge_dict_recursive(orig_v, v)
            elif isinstance(orig_v, list) and isinstance(v, list):
                original[k] = _unique(orig_v + v)

    return original


class Config:
    def __init__(self, conf):
        self.conf = conf

    def __getitem__(self, key):
        if key in self.conf:
            return self.conf[key]

        key_nodes = key.split('.')
        value = self.conf
        try:
            for key_node in key_nodes:
                value = value[key_node]
        except (KeyError, TypeError):
            logging.debug('Configure item "{0}" not found'.format(key))
            return None

        return value

    @classmethod
    def load(cls, args):
        conf = load_from_args(args)

        if args.config:
            conf_from_file = load_from_file(args.config)
            if conf_from_file:
                conf = merge_dict_recursive(conf, conf_from_file)

        conf = merge_dict_recursive(conf, DEFAULT_CONFIG)

        conf['upstreams'] = [parse_upstream(_) for _ in conf['upstreams']]

        return cls(conf)
