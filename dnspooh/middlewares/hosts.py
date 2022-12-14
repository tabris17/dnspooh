import logging
import pathlib
import functools

from ipaddress import ip_address

import https

from . import Middleware
from config import InvalidConfig
from scheme import Scheme


logger = logging.getLogger(__name__)


def _parse_line(ln):
    addr, hostname = ln.split(' ', 1)
    try:
        ip_addr = ip_address(addr.strip())
    except ValueError:
        raise InvalidConfig('Invalid ip address %s' % (addr, ))
    return ip_addr, hostname.strip()


class HostsMiddleware(Middleware):
    def _load_hosts_file(self, filename, overwrite=False):
        if filename in self.hosts and not overwrite:
            raise InvalidConfig('Duplicate hosts file %s' % (filename, ))
        self.hosts[filename] = _hosts = dict()
        try:
            with pathlib.Path(filename).open('r') as fp:
                self.files.append(filename)
                for ln in fp:
                    ln = ln.lstrip()
                    if ln == '' or ln.startswith('#'):
                        continue
                    ip_addr, hostname = _parse_line(ln)
                    if hostname in _hosts:
                        _hosts[hostname].append(ip_addr)
                    else:
                        _hosts[hostname] = [ip_addr]
        except:
            return False

    async def _load_hosts_url(self, url, overwrite=False):
        splited_url = url.split('|', 1)
        if len(splited_url) > 1:
            url, reload_interval = splited_url
            # TODO:
        if url in self.hosts and not overwrite:
            raise InvalidConfig('Duplicate hosts url %s' % (url, ))

        
        with await self.server.pool.connect('host', 80, Scheme.tcp) as conn:
            https.Client('baidu.com', conn)
        self.hosts[url] = dict()
        self.urls.append(url)

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

    async def handle(self, request, upstreams=None):
        response = await super().handle(request)
        return response
