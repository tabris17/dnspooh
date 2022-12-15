import logging
import pathlib
import ipaddress
import dnslib
import io
import functools

import https

from . import Middleware
from exceptions import InvalidConfig, HttpException
from scheme import Scheme


logger = logging.getLogger(__name__)


def _parse_line(ln):
    addr, hostname = ln.split(' ', 1)
    try:
        ip_addr = ipaddress.ip_address(addr.strip())
    except ValueError:
        raise InvalidConfig('Invalid ip address %s' % (addr, ))
    return ip_addr, hostname.strip()

def _parse_file(fp, hosts):
    for ln in fp:
        ln = ln.lstrip()
        if ln == '' or ln.startswith('#'):
            continue
        ip_addr, hostname = _parse_line(ln)
        if hostname in hosts:
            hosts[hostname].append(ip_addr)
        else:
            hosts[hostname] = [ip_addr]


class HostsMiddleware(Middleware):
    DEFAULT_TTL = 60

    def _load_hosts_file(self, filename, overwrite=False):
        if filename in self.hosts and not overwrite:
            raise InvalidConfig('Duplicate hosts file %s' % (filename, ))
        self.hosts[filename] = hosts = dict()
        try:
            with pathlib.Path(filename).open('r') as fp:
                self.files.append(filename)
                _parse_file(fp, hosts)
        except:
            return False
        return True


    async def _load_hosts_url(self, url, overwrite=False):
        splited_url = url.split('|', 1)
        if len(splited_url) > 1:
            url, reload_interval = splited_url
            # TODO:
        if url in self.hosts and not overwrite:
            raise InvalidConfig('Duplicate hosts url %s' % (url, ))

        try:
            response = await https.fetch(url, 
                                         self.server.handle, 
                                         self.server.pool, 
                                         self.server.proxy)
        except HttpException as exc:
            logger.warn(str(exc))
            return False
        self.hosts[url] = hosts = dict()
        self.urls.append(url)
        try:
            with io.StringIO(response.body.decode()) as fp:
                _parse_file(fp, hosts)
        except:
            return False
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
            for r in hosts[hostname]:
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
