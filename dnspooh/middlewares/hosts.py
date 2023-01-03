import logging
import pathlib
import ipaddress
import dnslib
import io
import functools

import https
import timers

from . import Middleware
from exceptions import InvalidConfig, HttpException


logger = logging.getLogger(__name__)


def _parse_line(ln):
    _addr, _hostname = ln.split(' ', 1)
    addr = _addr.strip()
    hostname = _hostname.strip()
    if addr == '-':
        return None, hostname
    try:
        ip_addr = ipaddress.ip_address(addr)
    except ValueError:
        raise InvalidConfig('Invalid ip address %s' % (addr, ))
    return ip_addr, hostname

def _parse_file(fp, hosts):
    for ln in fp:
        ln = ln.lstrip()
        if ln == '' or ln.startswith('#'):
            continue
        ip_addr, hostname = _parse_line(ln)
        if ip_addr is None:
            hosts[hostname] = None
        elif hostname not in hosts:
            hosts[hostname] = [ip_addr]
        elif hosts[hostname] is not None:
            hosts[hostname].append(ip_addr)


def _response_nxdomain(request):
    response = request.reply()
    response.header.rcode = getattr(dnslib.RCODE, 'NXDOMAIN')
    return response


class HostsMiddleware(Middleware):
    DEFAULT_TTL = 60

    def _load_hosts_file(self, filename, overwrite=False):
        logger.debug('Loading hosts file (filename=%s; overwrite=%s)' % (filename, overwrite))
        if filename in self.hosts and not overwrite:
            raise InvalidConfig('Duplicate hosts file %s' % (filename, ))
        self.hosts[filename] = hosts = dict()
        try:
            with pathlib.Path(filename).open('r') as fp:
                self.files.append(filename)
                _parse_file(fp, hosts)
        except Exception as exc:
            logger.warning('Failed to load hosts file (filename=%s; overwrite=%s; exc=%s)' % (filename, overwrite, exc))
            return False
        logger.debug('Succeeded to load hosts file (filename=%s; overwrite=%s)' % (filename, overwrite))
        return True

    async def _load_hosts_url(self, url, overwrite=False):
        logger.debug('Loading hosts url (url=%s; overwrite=%s)' % (url, overwrite))
        splited_url = url.split('|', 1)
        if len(splited_url) > 1:
            url, reload_interval = splited_url
            self.server.create_scheduled_task(
                functools.partial(self._load_hosts_url, url, True),
                timers.Timer(reload_interval), 
                '[SCHEDULE] fetching hosts (url=%s)' % (url, )
            )
        if url in self.hosts and not overwrite:
            raise InvalidConfig('Duplicate hosts url %s' % (url, ))

        try:
            response = await https.fetch(url, 
                                         self.server.handle, 
                                         self.server.pool, 
                                         self.server.proxy)
        except HttpException as exc:
            logger.warning('Failed to load hosts url (url=%s; overwrite=%s; exc=%s)' % (url, overwrite, exc))
            return False
        self.hosts[url] = hosts = dict()
        self.urls.append(url)
        try:
            with io.StringIO(response.body.decode()) as fp:
                _parse_file(fp, hosts)
        except Exception as exc:
            logger.warning('Failed to load hosts url (url=%s; overwrite=%s; exc=%s)' % (url, overwrite, exc))
            return False
        logger.debug('Succeeded to load hosts url (url=%s; overwrite=%s)' % (url, overwrite))
        return True

    async def bootstrap(self):
        success =  await super().bootstrap()
        if not success:
            return False
        for filename in self.filenames:
            if filename.startswith(('http://', 'https://')):
                await self._load_hosts_url(filename)
            else:
                self._load_hosts_file(filename)
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
        for _, hosts in self.hosts.items():
            if hostname not in hosts:
                continue
            ip_addrs = hosts[hostname]
            if ip_addrs is None:
                return _response_nxdomain(request)
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

    async def handle(self, request, upstreams=None):
        if request.header.q > 1 or request.q.qtype not in (dnslib.QTYPE.A, dnslib.QTYPE.AAAA):
            return await super().handle(request, upstreams)
        response = self.query(request)
        if not response:
            return await super().handle(request, upstreams)

        return response
