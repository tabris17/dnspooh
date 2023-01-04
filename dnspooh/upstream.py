import functools

from urllib.parse import urlsplit
from ipaddress import ip_address


DEFAULT_DOT_PORT = 853

DEFAULT_DNS_PORT = 53

DEFAULT_HTTPS_PORT = 443


class UpstreamCollection:
    def __init__(self, upstreams):
        self._upstreams = upstreams
        self._default_group = []
        self._grouped = dict()
        for upstream in upstreams:
            if upstream.group in self._grouped:
                self._grouped[upstream.group].append(upstream)
            else:
                self._grouped[upstream.group] = [upstream]
        self._named = {upstream.name: upstream for upstream in upstreams}
        self._sorted = upstreams.copy()
        self._pinned = None
        self.sort()

    def _cmp(self, up1, up2):
        if up1.name == self._pinned: return 1
        if up2.name == self._pinned: return -1
        return up1.priority - up2.priority

    def sort(self):
        self._sorted.sort(reverse=True, key=functools.cmp_to_key(self._cmp))
        for upstreams in self._grouped.values():
            upstreams.sort(reverse=True, key=functools.cmp_to_key(self._cmp))
        return self

    def all(self):
        return self._upstreams.copy()

    def group(self, name):
        self._grouped.get(name, self._default_group).copy()

    def sorted(self):
        return self._sorted.copy()

    def pinned(self, name):
        self._pinned = name
        return self


class Upstream:
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', '')
        self.proxy = kwargs.get('proxy')
        self.timeout = kwargs.get('timeout')
        self.group = kwargs.get('group')
        self.priority = kwargs.get('priority', 0)
        self.success = 0
        self.usage = 0
        self.disable = False

    def __repr__(self):
        return str(vars(self))

    def to_addr(self):
        return (self.host, self.port)

    def health(self, threshold):
        pass


class DnsUpstream(Upstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.host = kwargs['host']
        self.port = kwargs.get('port', DEFAULT_DNS_PORT)


class HttpsUpstream(Upstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.url = kwargs['url']
        parsed_url = urlsplit(self.url)
        self.hostname = parsed_url.hostname
        try:
            ip_address(parsed_url.hostname)
            self.host = parsed_url.hostname
        except ValueError:
            self.host = None
        self.port = parsed_url.port if parsed_url.port else DEFAULT_HTTPS_PORT
        self.path = parsed_url.path


class TlsUpstream(Upstream):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hostname = kwargs['host']
        try:
            ip_address(self.hostname)
            self.host = self.hostname
        except ValueError:
            self.host = None
        self.port = kwargs.get('port', DEFAULT_DOT_PORT)


def parse_upstream(server):
    if isinstance(server, dict):
        server_type = server.get('type', 'https' if 'url' in server else 'dns')
        if server_type == 'dns':
            upstream_class = DnsUpstream
        elif server_type == 'https':
            upstream_class = HttpsUpstream
        elif server_type == 'tls':
            upstream_class = TlsUpstream
        else:
            raise ValueError('Invalid upstream type')
        try:
            return upstream_class(**server)
        except KeyError as e:
            raise ValueError('Missing config key "%s" in "%s"' % (e.args[0], server))
    elif not isinstance(server, str):
        raise TypeError('Parameter server must be dict or string')

    parsed_url = urlsplit(
        server if server.startswith('https://') \
            else '//' + server
    )

    if parsed_url.scheme == 'https':
        return HttpsUpstream(url=server)

    if parsed_url.path == '' and \
       parsed_url.query == '' and \
       parsed_url.fragment == '':
        if parsed_url.port == DEFAULT_DOT_PORT:
            return TlsUpstream(host=parsed_url.hostname, port=DEFAULT_DOT_PORT)
        else:
            return DnsUpstream(host=parsed_url.hostname, 
                               port=DEFAULT_DNS_PORT \
                                   if parsed_url.port is None \
                                   else parsed_url.port)

    raise ValueError('Invalid upstream format "%s"' % (server, ))
