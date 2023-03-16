import enum
import urllib.parse
import random
import json
import os
import pathlib


def split_domain(name, reverse=True):
    dot_pos = name.find('.')
    if reverse:
        yield name
        while dot_pos > 0:
            yield name[dot_pos + 1:]
            dot_pos = name.find('.', dot_pos + 1)
    else:
        while dot_pos > 0:
            yield name[:dot_pos]
            dot_pos = name.find('.', dot_pos + 1)
        yield name


def s_addr(addr):
    if isinstance(addr, tuple):
        len_addr = len(addr)
        if len_addr == 2:
            return '[%s]:%d' % addr if ':' in addr[0] else '%s:%d' % addr
        elif len_addr == 4:
            return '[%s]:%d' % addr[:2]
    return str(addr)


def parse_addr(default_host, default_port, addr):
    result = urllib.parse.urlsplit('//' + addr)
    return (
        result.hostname or default_host, 
        result.port or default_port
    )


def flat_dict(d, key_prefix='', key_sep='.'):
    flatten = []
    for k, v in d.items():
        _k = key_prefix + key_sep + k
        if isinstance(v, dict):
            flatten.extend(flat_dict(v, _k, key_sep))
        else:
            flatten.append((_k[1:], v))
    return flatten


def prepare_path(file_path):
    file_path = pathlib.Path(file_path).resolve()
    dir_path = os.path.dirname(file_path)
    try:
        os.makedirs(dir_path)
    except FileExistsError:
        pass
    return file_path


class RandomInt:
    def __init__(self, begin, end):
        self.begin = begin
        self.end = end

    def __int__(self):
        return random.randrange(self.begin, self.end)
    
    def to_json(self):
        return 'random integer between %d to %d' % (self.begin, self.end)


class Scheme(enum.Enum):
    TCP = enum.auto()
    TLS = enum.auto()
    UDP = enum.auto()


class JsonEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, 'to_json'):
            return o.to_json()
        
        if hasattr(o, '__iter__'):
            return list(o)

        return super().default(o)
