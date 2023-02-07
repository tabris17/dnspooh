import functools

from urllib.parse import urlsplit
from ipaddress import ip_address


DEFAULT_DOT_PORT = 853

DEFAULT_DNS_PORT = 53

DEFAULT_HTTPS_PORT = 443


class UpstreamCollection:
    def __init__(self, upstreams, only_secure):
        if only_secure:
            upstreams = list(filter(
                lambda up: isinstance(up, (TlsUpstream, HttpsUpstream)), 
                upstreams))
        if not upstreams:
            raise ValueError('No upstream server available')
        self._upstreams = upstreams
        self._grouped = dict()
        for upstream in upstreams:
            for group in upstream.groups:
                if group in self._grouped:
                    self._grouped[group].append(upstream)
                else:
                    self._grouped[group] = [upstream]
        self._named = {upstream.name: upstream for upstream in upstreams}
        self._sorted = None
        self._selected = None
        self.sort()

    def _cmp(self, up1, up2):
        if up1.name == self._selected: return 1
        if up2.name == self._selected: return -1
        return up1.priority - up2.priority

    def sort(self):
        self._sorted = self.all()
        self._sorted.sort(reverse=True, key=functools.cmp_to_key(self._cmp))
        for group_name, group_upstreams in self._grouped.items():
            group_upstreams = group_upstreams.copy()
            group_upstreams.sort(reverse=True, key=functools.cmp_to_key(self._cmp))
            self._grouped[group_name] = group_upstreams
        return self

    def all(self):
        return self._upstreams.copy()

    def group(self, name):
        return self._grouped[name]

    def has_group(self, name):
        return name in self._grouped

    def sorted(self):
        if self._sorted is None:
            self.sort()
        return self._sorted

    def select(self, name):
        self._selected = name
        return self.sort()

    @property
    def primary(self):
        return self._sorted[0]

    def __getitem__ (self, name):
        return self._named[name]

    def __contains__(self, name):
        return name in self._named


class Upstream:
    def __init__(self, **kwargs):
        self.name = kwargs.get('name')
        if not isinstance(self.name, str) or self.name == '':
            raise ValueError('Upstream name must be a non-empty string')
        self.proxy = kwargs.get('proxy')
        timeout_ms = kwargs.get('timeout')
        self.timeout_sec = timeout_ms / 1000 if timeout_ms is not None else None
        self.groups = kwargs.get('groups', [])
        if not isinstance(self.groups, list):
            raise ValueError('Upstream groups must be a list')
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
        return HttpsUpstream(name=server, url=server)

    if parsed_url.path == '' and \
       parsed_url.query == '' and \
       parsed_url.fragment == '':
        if parsed_url.port == DEFAULT_DOT_PORT:
            return TlsUpstream(name=server, host=parsed_url.hostname, port=DEFAULT_DOT_PORT)
        else:
            return DnsUpstream(name=server, 
                               host=parsed_url.hostname, 
                               port=DEFAULT_DNS_PORT \
                                   if parsed_url.port is None \
                                   else parsed_url.port)

    raise ValueError('Invalid upstream format "%s"' % (server, ))
