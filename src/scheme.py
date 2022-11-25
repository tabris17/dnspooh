import enum


class Scheme(enum.Enum):
    tcp = enum.auto()
    tls = enum.auto()
    udp = enum.auto()
