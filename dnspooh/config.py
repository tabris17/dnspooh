import logging
import yaml
import pathlib

try:
    from yaml import CSafeLoader as YAMLLoader
except ImportError:
    from yaml import SafeLoader as YAMLLoader

from .upstream import *
from .proxy import *
from .exceptions import InvalidConfig


CONFIG_FILE = 'config.yml'

DEFAULT_LISTEN_HOST = '0.0.0.0'

LISTEN_ADDRESS = '%s:%d' % (DEFAULT_LISTEN_HOST, DEFAULT_DNS_PORT)

UPSTREAM_TIMEOUT = 5000

HTTP_TIMEOUT = 10000

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
        'groups': [
            'cloudflare',
            'global',
        ]
    },
    {
        'name': 'cloudflare-2',
        'type': 'dns',
        'host': '1.0.0.1',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'cloudflare',
            'global',
        ],
    },
    {
        'name': 'cloudflare-ipv6-1',
        'type': 'dns',
        'host': '2606:4700:4700::1111',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'cloudflare',
            'global',
        ],
    },
    {
        'name': 'cloudflare-ipv6-2',
        'type': 'dns',
        'host': '2606:4700:4700::1001',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'cloudflare',
            'global',
        ],
    },
    {
        'name': 'cloudflare-tls',
        'type': 'tls',
        'host': '1.1.1.1',
        'port': DEFAULT_DOT_PORT,
        'groups': [
            'cloudflare',
            'global',
        ],
        'priority': 1,
    },
    {
        'name': 'cloudflare-https',
        'type': 'https',
        'url': 'https://1.1.1.1/dns-query',
        'groups': [
            'cloudflare',
            'global',
        ],
    },{
        'name': 'google-1',
        'type': 'dns',
        'host': '8.8.8.8',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'google',
            'global',
        ],
    },
    {
        'name': 'google-2',
        'type': 'dns',
        'host': '8.8.4.4',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'google',
            'global',
        ],
    },
    {
        'name': 'google-tls',
        'type': 'tls',
        'host': '8.8.8.8',
        'port': DEFAULT_DOT_PORT,
        'groups': [
            'google',
            'global',
        ],
    },
    {
        'name': 'google-https',
        'type': 'https',
        'url': 'https://dns.google/dns-query',
        'groups': [
            'google',
            'global',
        ],
    },
    {
        'name': 'alidns-1',
        'type': 'dns',
        'host': '223.6.6.6',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'alidns',
            'cn',
        ],
    },
    {
        'name': 'alidns-2',
        'type': 'dns',
        'host': '223.5.5.5',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'alidns',
            'cn',
        ],
    },
    {
        'name': 'alidns-ipv6-1',
        'type': 'dns',
        'host': '2400:3200::1',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'alidns',
            'cn',
        ],
    },
    {
        'name': 'alidns-ipv6-2',
        'type': 'dns',
        'host': '2400:3200:baba::1',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'alidns',
            'cn',
        ],
    },
    {
        'name': 'alidns-tls',
        'type': 'tls',
        'host': 'dns.alidns.com',
        'port': DEFAULT_DOT_PORT,
        'groups': [
            'alidns',
            'cn',
        ],
    },
    {
        'name': 'alidns-https',
        'type': 'https',
        'url': 'https://dns.alidns.com/dns-query',
        'groups': [
            'alidns',
            'cn',
        ],
    },
    {
        'name': '114dns-1',
        'type': 'dns',
        'host': '114.114.114.114',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            '114dns',
            'cn',
        ],
    },
    {
        'name': '114dns-2',
        'type': 'dns',
        'host': '114.114.115.115',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            '114dns',
            'cn',
        ],
    },
    {
        'name': 'onedns-1',
        'type': 'dns',
        'host': '117.50.10.10',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'onedns',
            'cn',
        ],
    },
    {
        'name': 'onedns-2',
        'type': 'dns',
        'host': '52.80.52.52',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'onedns',
            'cn',
        ],
    },
    {
        'name': 'onedns-ipv6-1',
        'type': 'dns',
        'host': '2400:7fc0:849e:200::4',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'onedns',
            'cn',
        ],
    },
    {
        'name': 'onedns-ipv6-2',
        'type': 'dns',
        'host': '2404:c2c0:85d8:901::4',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'onedns',
            'cn',
        ],
    },
    {
        'name': 'dnspod',
        'type': 'dns',
        'host': '119.29.29.29',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-tls-1',
        'type': 'tls',
        'host': '120.53.53.53',
        'port': DEFAULT_DOT_PORT,
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-tls-2',
        'type': 'tls',
        'host': '1.12.12.12',
        'port': DEFAULT_DOT_PORT,
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-tls-3',
        'type': 'tls',
        'host': 'dot.pub',
        'port': DEFAULT_DOT_PORT,
        'disable': True,
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-ipv6',
        'type': 'dns',
        'host': '2402:4e00::',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-https-1',
        'type': 'https',
        'url': 'https://1.12.12.12/dns-query',
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-https-2',
        'type': 'https',
        'url': 'https://120.53.53.53/dns-query',
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'dnspod-https-3',
        'type': 'https',
        'url': 'https://doh.pub/dns-query',
        'disable': True,
        'groups': [
            'dnspod',
            'cn',
        ],
    },
    {
        'name': 'baidu',
        'type': 'dns',
        'host': '180.76.76.76',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'baidu',
            'cn',
        ],
    },
    {
        'name': 'baidu-ipv6',
        'type': 'dns',
        'host': '2400:da00::6666',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'baidu',
            'cn',
        ],
    },
    {
        'name': 'opendns-1',
        'type': 'dns',
        'host': '208.67.222.222',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'opendns',
            'global',
        ],
    },
    {
        'name': 'opendns-2',
        'type': 'dns',
        'host': '208.67.220.220',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'opendns',
            'global',
        ],
    },
    {
        'name': 'adguard-1',
        'type': 'dns',
        'host': '94.140.14.14',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'adguard',
            'global',
        ],
    },
    {
        'name': 'adguard-2',
        'type': 'dns',
        'host': '94.140.15.15',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'adguard',
            'global',
        ],
    },
    {
        'name': 'adguard-ipv6-1',
        'type': 'dns',
        'host': '2a10:50c0::ad1:ff',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'adguard',
            'global',
        ],
    },
    {
        'name': 'adguard-ipv6-2',
        'type': 'dns',
        'host': '2a10:50c0::ad2:ff',
        'port': DEFAULT_DNS_PORT,
        'groups': [
            'adguard',
            'global',
        ],
    },
    {
        'name': 'adguard-tls',
        'type': 'tls',
        'host': 'dns.adguard-dns.com',
        'port': DEFAULT_DOT_PORT,
        'groups': [
            'adguard',
            'global',
        ],
    },
]

DEFAULT_CONFIG = {
    'secure': True,
    'debug': False,
    'listen': LISTEN_ADDRESS,
    'timeout': UPSTREAM_TIMEOUT,
    'upstreams': BUILTIN_UPSTREAMS,
    'proxy': None,
    'geoip': None,
    'stats': {
        'max_size': STATS_MAX_LEN,
    },
    'cache': {
        'max_size': CACHE_MAX_SIZE,
        'ttl': CACHE_TTL,
    },
    'log': {
        'path': 'access.log',
        'trace': True,
        'payload': True,
    },
    'http': {
        'host': HTTP_HOST,
        'port': HTTP_PORT,
        'timeout': HTTP_TIMEOUT,
        'static_files': 'web',
        'disable': True,
    },
    'middlewares': ['cache'],
}


logger = logging.getLogger(__name__)


def _load_from_file(file_path):
    if not file_path.is_file():
        raise FileNotFoundError('Cannot load config file "%s"' % (file_path.absolute(), ))

    def yaml_include(loader, node):
        node_value = loader.construct_scalar(node)
        with file_path.parent.joinpath(node_value).open() as stream:
            return yaml.load(stream, Loader=YAMLLoader)

    def yaml_path(loader, node):
        node_value = loader.construct_scalar(node)
        return str(file_path.parent.joinpath(node_value).absolute())

    YAMLLoader.add_constructor('!include', yaml_include)
    YAMLLoader.add_constructor('!path', yaml_path)
    with file_path.open() as stream:
        return yaml.load(stream, Loader=YAMLLoader)


def _load_from_args(args):
    conf = dict()

    if args.debug is not None:
        conf['debug'] = args.debug

    if args.listen is not None:
        conf['listen'] = args.listen

    if args.timeout is not None:
        conf['timeout'] = args.timeout

    if args.upstreams is not None:
        conf['upstreams'] = args.upstreams
        conf['secure'] = False

    return conf


def _merge_dict_recursive(original, addition, reserved = []):
    def _unique(l):
        unique_l = list()
        for _ in l:
            if _ not in unique_l:
                unique_l.append(_)
        return unique_l

    def _reserved(k):
        prefix = k + '.'
        return [_[len(prefix):] for _ in reserved if _.startswith(prefix)]

    for k, v in addition.items():
        if k not in original:
            if v is not None:
                original[k] = v
        elif k in reserved:
            continue
        else:
            orig_v = original[k]
            if isinstance(orig_v, dict) and isinstance(v, dict):
                _merge_dict_recursive(orig_v, v, _reserved(k))
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
        conf = _load_from_args(args)

        if args.config:
            config_file = pathlib.Path(args.config)
            conf = _merge_dict_recursive(conf, _load_from_file(config_file))
            logger.info('Config file "%s" loaded', config_file.absolute())
        else:
            config_file = pathlib.Path(CONFIG_FILE)
            if config_file.is_file():
               conf = _merge_dict_recursive(conf, _load_from_file(config_file))
               logger.info('Default config file "%s" loaded', config_file.absolute())

        conf = _merge_dict_recursive(conf, DEFAULT_CONFIG, ['upstreams'])

        try:
            conf['proxy'] = parse_proxy(conf.get('proxy'))
            conf['upstreams'] = [parse_upstream(_) for _ in conf['upstreams'] \
                                    if not isinstance(_, dict) or not _.get('disable', False)]
        except ValueError as exc:
            raise InvalidConfig(exc)

        return cls(conf)
