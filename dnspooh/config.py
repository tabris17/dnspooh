import logging
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

from upstream import *
from proxy import *
from exceptions import InvalidConfig


VERSION = '0.1.0'

LISTEN_HOST = '0.0.0.0'

UPSTREAM_TIMEOUT = 5

HTTP_TIMEOUT = 10

HTTP_HOST = '127.0.0.1'

HTTP_PORT = 8964

CACHE_MAX_SIZE = 4096

CACHE_TTL = 86400

STATS_MAX_LEN = 1000

BUILTIN_UPSTREAMS = [
    {
        'name': 'cloudflare-1',
        'type': 'dns',
        'host': '1.1.1.1',
        'port': DEFAULT_DNS_PORT,
        'group': 'cloudflare',
    },
    {
        'name': 'cloudflare-2',
        'type': 'dns',
        'host': '1.0.0.1',
        'port': DEFAULT_DNS_PORT,
        'group': 'cloudflare',
    },
    {
        'name': 'cloudflare-ipv6-1',
        'type': 'dns',
        'host': '2606:4700:4700::1111',
        'port': DEFAULT_DNS_PORT,
        'group': 'cloudflare',
    },
    {
        'name': 'cloudflare-ipv6-2',
        'type': 'dns',
        'host': '2606:4700:4700::1001',
        'port': DEFAULT_DNS_PORT,
        'group': 'cloudflare',
    },
    {
        'name': 'cloudflare-tls',
        'type': 'tls',
        'host': '1.1.1.1',
        'port': DEFAULT_DOT_PORT,
        'group': 'cloudflare',
        'priority': 1,
    },
    {
        'name': 'cloudflare-https',
        'type': 'https',
        'url': 'https://1.1.1.1/dns-query',
        'group': 'cloudflare',
    },{
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
        'name': 'google-tls',
        'type': 'tls',
        'host': '8.8.8.8',
        'port': DEFAULT_DOT_PORT,
        'group': 'google',
    },
    {
        'name': 'google-https',
        'type': 'https',
        'url': 'https://dns.google/dns-query',
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
    {
        'name': 'alidns-ipv6-1',
        'type': 'dns',
        'host': '2400:3200::1',
        'port': DEFAULT_DNS_PORT,
        'group': 'alidns',
    },
    {
        'name': 'alidns-ipv6-2',
        'type': 'dns',
        'host': '2400:3200:baba::1',
        'port': DEFAULT_DNS_PORT,
        'group': 'alidns',
    },
    {
        'name': 'alidns-tls',
        'type': 'tls',
        'host': 'dns.alidns.com',
        'port': DEFAULT_DOT_PORT,
        'group': 'alidns',
    },
    {
        'name': 'alidns-https',
        'type': 'https',
        'url': 'https://dns.alidns.com/dns-query',
        'group': 'alidns',
    },
    {
        'name': '114dns-1',
        'type': 'dns',
        'host': '114.114.114.114',
        'port': DEFAULT_DNS_PORT,
        'group': '114dns',
    },
    {
        'name': '114dns-2',
        'type': 'dns',
        'host': '114.114.115.115',
        'port': DEFAULT_DNS_PORT,
        'group': '114dns',
    },
    {
        'name': 'onedns-1',
        'type': 'dns',
        'host': '117.50.10.10',
        'port': DEFAULT_DNS_PORT,
        'group': 'onedns',
    },
    {
        'name': 'onedns-2',
        'type': 'dns',
        'host': '52.80.52.52',
        'port': DEFAULT_DNS_PORT,
        'group': 'onedns',
    },
    {
        'name': 'onedns-ipv6-1',
        'type': 'dns',
        'host': '2400:7fc0:849e:200::4',
        'port': DEFAULT_DNS_PORT,
        'group': 'onedns',
    },
    {
        'name': 'onedns-ipv6-2',
        'type': 'dns',
        'host': '2404:c2c0:85d8:901::4',
        'port': DEFAULT_DNS_PORT,
        'group': 'onedns',
    },
    {
        'name': 'dnspod',
        'type': 'dns',
        'host': '119.29.29.29',
        'port': DEFAULT_DNS_PORT,
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-tls-1',
        'type': 'tls',
        'host': '120.53.53.53',
        'port': DEFAULT_DOT_PORT,
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-tls-2',
        'type': 'tls',
        'host': '1.12.12.12',
        'port': DEFAULT_DOT_PORT,
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-tls-3',
        'type': 'tls',
        'host': 'dot.pub',
        'port': DEFAULT_DOT_PORT,
        'disable': True,
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-ipv6',
        'type': 'dns',
        'host': '2402:4e00::',
        'port': DEFAULT_DNS_PORT,
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-https-1',
        'type': 'https',
        'url': 'https://1.12.12.12/dns-query',
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-https-2',
        'type': 'https',
        'url': 'https://120.53.53.53/dns-query',
        'group': 'dnspod',
    },
    {
        'name': 'dnspod-https-3',
        'type': 'https',
        'url': 'https://doh.pub/dns-query',
        'disable': True,
        'group': 'dnspod',
    },
    {
        'name': 'baidu',
        'type': 'dns',
        'host': '180.76.76.76',
        'port': DEFAULT_DNS_PORT,
        'group': 'baidu',
    },
    {
        'name': 'baidu-ipv6',
        'type': 'dns',
        'host': '2400:da00::6666',
        'port': DEFAULT_DNS_PORT,
        'group': 'baidu',
    },
    {
        'name': 'opendns-1',
        'type': 'dns',
        'host': '208.67.222.222',
        'port': DEFAULT_DNS_PORT,
        'group': 'opendns',
    },
    {
        'name': 'opendns-2',
        'type': 'dns',
        'host': '208.67.220.220',
        'port': DEFAULT_DNS_PORT,
        'group': 'opendns',
    },
    {
        'name': 'adguard-1',
        'type': 'dns',
        'host': '94.140.14.14',
        'port': DEFAULT_DNS_PORT,
        'group': 'adguard',
    },
    {
        'name': 'adguard-2',
        'type': 'dns',
        'host': '94.140.15.15',
        'port': DEFAULT_DNS_PORT,
        'group': 'adguard',
    },
]

DEFAULT_CONFIG = {
    'secret': True,
    'debug': False,
    'host': LISTEN_HOST,
    'port': DEFAULT_DNS_PORT,
    'timeout': UPSTREAM_TIMEOUT,
    'upstreams': BUILTIN_UPSTREAMS,
    'proxy': None,
    'stats': {
        'max_size': STATS_MAX_LEN,
    },
    'cache': {
        'max_size': CACHE_MAX_SIZE,
        'ttl': CACHE_TTL,
    },
    'hosts': [
        'hosts',
    ],
    'block': [
        'block.txt',
    ],
    'http': {
        'host': HTTP_HOST,
        'port': HTTP_PORT,
        'timeout': HTTP_TIMEOUT,
        'static_files': 'web',
    },
    'middlewares': [],
}


logger = logging.getLogger(__name__)


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

    def _get(self, key):
        if key in self.conf:
            return self.conf[key]
        key_nodes = key.split('.')
        value = self.conf
        for key_node in key_nodes:
            value = value[key_node]
        return value

    def get(self, key, default=None):
        try:
            return self._get(key)
        except (KeyError, TypeError):
            return default

    def __getitem__(self, key):
        try:
            return self._get(key)
        except (KeyError, TypeError):
            logger.warning('Configure item "%s" not found', key)

    def exists(self, key):
        try:
            self._get(key)
            return True
        except (KeyError, TypeError):
            return False

    @classmethod
    def load(cls, args):
        conf = load_from_args(args)

        if args.config:
            conf_from_file = load_from_file(args.config)
            if conf_from_file:
                conf = merge_dict_recursive(conf, conf_from_file)

        conf = merge_dict_recursive(conf, DEFAULT_CONFIG)

        try:
            conf['proxy'] = parse_proxy(conf.get('proxy'))
            conf['upstreams'] = [parse_upstream(_) for _ in conf['upstreams'] \
                                    if not _.get('disable', False)]
        except ValueError as e:
            raise InvalidConfig(e)

        return cls(conf)
