import logging
import pathlib

from ipaddress import ip_address

from . import Middleware
from config import InvalidConfig


logger = logging.getLogger(__name__)


class HostsMiddleware(Middleware):
    def _parse_line(self, ln):
        addr, hostname = ln.split(' ', 1)
        try:
            ip_addr = ip_address(addr.strip())
        except ValueError:
            raise InvalidConfig('Invalid ip address %s' % (addr, ))
        self.hosts[hostname.strip()] = ip_addr

    def _parse_file(self, stream):
        for ln in stream:
            ln = ln.strip()
            if ln == '' or ln.startswith('#'):
                continue
            self._parse_line(ln)

    def _load_hosts_file(self, filename):
        try:
            with pathlib.Path(filename).open('r') as fp:
                self.hosts_files.append(filename)
                self._parse_file(fp)
        except:
            return False

    def _load_hosts_url(self, url):
        self.hosts_urls.append(url)

    def __init__(self, next, *items):
        super().__init__(next)
        self.hosts = dict()
        self.hosts_files = []
        self.hosts_urls = []
        for item in items:
            if item.startswith(('http://', 'https://')):
                self._load_hosts_url(item)
            else:
                self._load_hosts_file(item)

    async def handle(self, request, upstreams=None):
        response = await super().handle(request)
        return response
