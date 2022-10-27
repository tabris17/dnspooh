import logging
import ipaddress
import dnslib
import functools

from . import Middleware, load_config
from ..exceptions import InvalidConfig
from .. import timers


logger = logging.getLogger(__name__)


def _parse_config(fp):
    hosts = dict()
    line_no = 1

    for ln in fp:
        ln = ln.lstrip()
        if ln == '' or ln.startswith('#'):
            continue
        _addr, _hostname = ln.split(' ', 1)
        addr = _addr.strip()
        hostname = _hostname.strip()
        try:
            ip_addr = ipaddress.ip_address(addr)
        except ValueError:
            raise InvalidConfig('Invalid ip address %s in line %d' % (addr, line_no))
        if hostname in hosts:
            hosts[hostname].append(ip_addr)
        else:
            hosts[hostname] = [ip_addr]
        line_no += 1
    return hosts


class HostsMiddleware(Middleware):
    DEFAULT_TTL = 60

    async def load_config(self, filename):
        try:
            self.hosts[filename] = await load_config(filename, self.server, _parse_config)
        except Exception as exc:
            logger.warning('Failed to load hosts file "%s": %s', filename, exc)
            return False
        logger.info('Hosts file "%s" loaded', filename)
        return True

    def is_loaded(self, filename):
        return filename in self.hosts

    async def bootstrap(self):
        if not await super().bootstrap():
            return False
        for _file in self.filenames:
            if isinstance(_file, list):
                filename, refresh_interval = _file
                self.server.create_scheduled_task(
                    functools.partial(self.load_config, filename),
                    timers.Timer(refresh_interval), 
                    '[SCHEDULE] fetching hosts file %s' % (filename, )
                )
            else:
                filename = _file
            if not self.is_loaded(filename):
                await self.load_config(filename)
            else:
                raise InvalidConfig('Duplicate hosts file %s' % (filename, ))
        return True

    def __init__(self, next, *filenames):
        super().__init__(next)
        self.hosts = dict()
        self.files = []
        self.urls = []
        self.filenames = filenames

    def query(self, request):
        hostname = request.q.qname.idna().rstrip('.')
        qtype = request.q.qtype
        response = request.reply()
        for hosts in self.hosts.values():
            if hostname not in hosts:
                continue
            ip_addrs = hosts[hostname]
            for r in ip_addrs:
                if isinstance(r, ipaddress.IPv6Address) and qtype == dnslib.QTYPE.AAAA:
                    response.add_answer(dnslib.RR(
                        hostname, qtype, 
                        rdata=dnslib.AAAA(str(r)), 
                        ttl=self.DEFAULT_TTL
                    ))
                elif isinstance(r, ipaddress.IPv4Address) and qtype == dnslib.QTYPE.A:
                    response.add_answer(dnslib.RR(
                        hostname, qtype, 
                        rdata=dnslib.A(str(r)), 
                        ttl=self.DEFAULT_TTL
                    ))
        return response if response.header.a > 0 else None

    async def handle(self, request, **kwargs):
        if request.q.qtype not in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA):
            return await super().handle(request, **kwargs)
        response = self.query(request)
        if not response:
            return await super().handle(request, **kwargs)

        return response
