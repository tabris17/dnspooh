import logging
import dnslib
import functools
import ipaddress

from . import Middleware, load_config
from .. import timers
from ..exceptions import InvalidConfig
from ..helpers import split_domain


logger = logging.getLogger(__name__)


def _nxdomain(request):
    response = request.reply()
    response.header.rcode = dnslib.RCODE.NXDOMAIN
    return response


def _parse_config(fp):
    domain_blacklist = set()
    ip_blacklist = set()

    for ln in fp:
        ln = ln.strip()
        if ln == '' or ln.startswith('#'):
            continue
        
        if ln.startswith('ip:'):
            ip_blacklist.add(ipaddress.ip_address(ln[3:].strip()))
        else:
            domain_blacklist.add(ln)
    return domain_blacklist, ip_blacklist


class BlockMiddleware(Middleware):
    async def load_config(self, filename):
        try:
            self.blacklists[filename] = await load_config(filename, self.server, _parse_config)
        except Exception as exc:
            logger.warning('Failed to load blacklist "%s": %s', filename, exc)
            return False
        logger.info('Blacklist "%s" loaded', filename)
        return True

    def is_loaded(self, filename):
        return filename in self.blacklists

    async def bootstrap(self):
        if not await super().bootstrap():
            return False
        for _file in self.filenames:
            if isinstance(_file, list):
                filename, refresh_interval = _file
                if not self.is_loaded(filename):
                    self.server.create_scheduled_task(
                        functools.partial(self.load_config, filename),
                        timers.Timer(refresh_interval), 
                        '[SCHEDULE] fetching blacklist %s' % (filename, )
                    )
            else:
                filename = _file
            if self.is_loaded(filename):
                raise InvalidConfig('Duplicate blacklist %s' % (filename, ))
            await self.load_config(filename)
        return True

    def __init__(self, *filenames):
        self.blacklists = dict()
        self.filenames = filenames

    async def handle(self, request, **kwargs):
        if request.q.qtype not in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA):
            return await super().handle(request, **kwargs)

        domain_parts = list(split_domain(request.q.qname.idna().rstrip('.')))
        for blacklist, _ in self.blacklists.values():
            for part in domain_parts:
                if part in blacklist:
                    return _nxdomain(request)

        response = await super().handle(request, **kwargs)
        if response is None: return

        for rr in filter(lambda rr: rr.rtype in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA), response.rr):
            ip_addr = ipaddress.ip_address(str(rr.rdata))
            for _, blacklist in self.blacklists.values():
                if ip_addr in blacklist:
                    return _nxdomain(request)

        return response
