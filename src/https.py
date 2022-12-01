import io
import logging
import email.parser
import email.policy

from http import HTTPStatus, HTTPMethod
from http.client import HTTPMessage


logger = logging.getLogger(__name__)


class Request:
    HTTP_VERSION = 'HTTP/1.1'

    def __init__(self, method, url, host, headers):
        self.method = method
        self.url = url
        self.host = host
        self.headers = HTTPMessage(email.policy.HTTP)
        self.headers.add_header('Host', host)
        self.headers.add_header('Accept-Encoding', 'identity')
        self.headers.add_header('Connection', 'keep-alive')
        for header in headers:
            self.headers.add_header(*header)

    def as_bytes(self):
        method_header = '%s %s %s\r\n' % (self.method, self.url, self.HTTP_VERSION)
        return method_header.encode() + self.headers.as_bytes()

    def __bytes__(self):
        return self.as_bytes()

    def __repr__(self):
        return self.as_bytes().decode()

    async def send_to(self, writer):
        writer.write(self.as_bytes())
        return await writer.drain()


class Response:
    def __init__(self, reader):
        self._reader = reader

    async def end(self):
        raw_headers = await self._reader.readuntil(b'\r\n\r\n')
        fp = io.StringIO(raw_headers.decode())
        self.status = fp.readline()
        self.version, status_code, _ = self.status.split(' ', 2)
        self.status_code = HTTPStatus(int(status_code))
        self.headers = email.parser.Parser(_class=HTTPMessage).parse(fp)
        self.body = None
        if self.headers.get('Transfer-Encoding') == 'chunked':
            self.body = await self._reader.readuntil(b'\r\n\r\n')
        else:
            try:
                content_length = int(self.headers['Content-Length'])
                self.body = await self._reader.readexactly(content_length)
            except TypeError:
                pass
        return self

    def __repr__(self):
        return self.status + str(self.headers) + ('(None)' if self.body is None else str(self.body))


class Client:
    def __init__(self, conn):
        self.conn = conn

    async def get(self, url, hostname, headers=[]):
        conn = self.conn
        request = Request(HTTPMethod.GET, url, hostname, headers)
        logger.debug('HTTP request:\n%s', request)
        await request.send_to(conn.writer)
        response = await Response(conn.reader).end()
        logger.debug('HTTP response:\n%s', response)
        return response
