from collections import namedtuple
from urllib.parse import urlsplit
from ipaddress import ip_address


DEFAULT_DOT_PORT = 853

DEFAULT_DNS_PORT = 53

DEFAULT_HTTPS_PORT = 443


class Stats:
    Record = namedtuple('Record', ['datetime', 'success', 'time_cost'])

    def __init__(self):
        self.usage = 0
        self.failure = 0
        self.success = 0
        self.last_access = None

    def __repr__(self):
        return str(vars(self))

    def log(self):
        pass

    def error(self):
        pass

    def timeout(self):
        pass


class Upstreams:
    def __init__(self):
        self._default = list()
        self._grouped = dict()


class Upstream:
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', '')
        self.proxy = kwargs.get('proxy')
        self.timeout = kwargs.get('timeout')
        self.group = kwargs.get('group')
        self.priority = kwargs.get('priority', 0)
        self.stats = Stats()

    def __repr__(self):
        return str(vars(self))

    def to_addr(self):
        return (self.host, self.port)


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
