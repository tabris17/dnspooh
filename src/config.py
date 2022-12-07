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

UPSTREAM_TIMEOUT = 1

CACHE_MAX_SIZE = 4096

CACHE_TTL = 3600

STATS_MAX_LEN = 1000

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
    'stats': {
        'max_size': STATS_MAX_LEN,
    },
    'cache': {
        'max_size': CACHE_MAX_SIZE,
        'ttl': CACHE_TTL,
    },
    'http': {
        'host': '127.0.0.1',
        'port': 8964,
    },
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

    def __getitem__(self, key):
        if key in self.conf:
            return self.conf[key]

        key_nodes = key.split('.')
        value = self.conf
        try:
            for key_node in key_nodes:
                value = value[key_node]
        except (KeyError, TypeError):
            logger.warning('Configure item "%s" not found', key)
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

        try:
            conf['proxy'] = parse_proxy(conf.get('proxy'))
            conf['upstreams'] = [parse_upstream(_) for _ in conf['upstreams'] \
                                    if not _.get('disable', False)]
            conf['upstreams'].sort(reverse=True, key=lambda upstm: upstm.priority)
        except ValueError as e:
            raise InvalidConfig(e)

        return cls(conf)
