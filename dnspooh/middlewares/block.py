import logging
import ipaddress
import dnslib
import functools

import timers

from . import Middleware, load_config
from exceptions import InvalidConfig


logger = logging.getLogger(__name__)


def _nxdomain(request):
    response = request.reply()
    response.header.rcode = getattr(dnslib.RCODE, 'NXDOMAIN')
    return response


def _parse_config(fp):
    blacklist = set()

    for ln in fp:
        ln = ln.lstrip()
        if ln == '' or ln.startswith('#'):
            continue
        blacklist.add(ln)
    return blacklist


class BlockMiddleware(Middleware):
    async def load_config(self, filename):
        try:
            self.blacklists[filename] = await load_config(filename, self.server, _parse_config)
        except Exception as exc:
            logger.warning('Failed to load blacklist %s: %s', filename, exc)
            return False
        logger.info('Succeeded to load blacklist %s', filename)
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

    def __init__(self, next, *filenames):
        super().__init__(next)
        self.blacklists = dict()
        self.files = []
        self.urls = []
        self.filenames = filenames

    async def handle(self, request, **kwargs):
        if request.q.qtype not in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA):
            return await super().handle(request, **kwargs)

        hostname = request.q.qname.idna().rstrip('.')
        for blacklist in self.blacklists.values():
            if hostname in blacklist:
                return _nxdomain(request)

            dot_pos = hostname.find('.')
            while dot_pos > 0:
                suffix_hostname = hostname[dot_pos + 1:]
                if suffix_hostname in blacklist:
                    return _nxdomain(request)
                dot_pos = hostname.find('.', dot_pos + 1)                

        return await super().handle(request, **kwargs)
