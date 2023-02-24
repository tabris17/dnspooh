import enum
import urllib.parse
import random


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


class RandomInt:
    def __init__(self, begin, end):
        self.begin = begin
        self.end = end

    def __int__(self):
        return random.randrange(self.begin, self.end)


class Scheme(enum.Enum):
    tcp = enum.auto()
    tls = enum.auto()
    udp = enum.auto()
