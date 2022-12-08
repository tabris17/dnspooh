import asyncio
import io
import logging
import email.parser
import email.policy

from email.mime.multipart import MIMEMultipart
from http import HTTPStatus, HTTPMethod
from http.client import HTTPMessage
from urllib.parse import urlencode, urlsplit, parse_qs

from exceptions import HttpRequestException, HttpResponseException


HTTP_VERSION = 'HTTP/1.1'

logger = logging.getLogger(__name__)


class Request:
    class FormData:
        @classmethod
        def parse(cls, content_type, data):
            form = cls()
            if content_type == 'applicaton/x-www-urlencoded':
                #self._form = parse_qs(self.body.decode())
                pass
            elif content_type == 'multipart/form-data':
                pass
            return form

    async def read(self, reader):
        try:
            start_line, self.headers, self.body = await _read_http_message(reader)
            method, self.url, self.version = start_line.split(' ', 2)
            self.method = HTTPMethod(method)
        except Exception as exc:
            raise HttpRequestException(exc)

    def _parse_query(self):
        if hasattr(self, '_query'): return
        parsed_url = urlsplit(self.url)
        self._query = parse_qs(parsed_url.query) if parsed_url.query else dict()

    def get(self, name, default=None):
        self._parse_query()
        if name in self._query:
            return self._query[name].pop()
        return default

    def get_all(self, name):
        self._parse_query()
        if name in self._query:
            return self._query[name]
        return []

    def _parse_form(self):
        if hasattr(self, '_form'): return
        content_type = self.headers.get('Conetent-Type')
        self._form = self.FormData.parse(content_type, self.body)

    @property
    def form(self):
        return self._form

    def __init__(self):
        self.method = None
        self.url = None
        self.version = HTTP_VERSION
        self.headers = HTTPMessage(email.policy.HTTP)
        self.body = None

    def __repr__(self):
        if self.method is None or self.url is None:
            return '<%s>' % self.__class__.__name__
        return '<%s: %s %r>' % (
            self.__class__.__name__,
            self.method,
            self.url,
        )


class Response:
    async def read(self, reader):
        try:
            start_line, self.headers, self.body = await _read_http_message(reader)
            self.version, status, self.reason = start_line.split(' ', 2)
            self.status = HTTPStatus(int(status))
        except Exception as exc:
            raise HttpResponseExcepion(exc)

    def __init__(self):
        self.status = None
        self.reason = None
        self.version = HTTP_VERSION
        self.headers = HTTPMessage(email.policy.HTTP)
        self.body = None

    def __repr__(self):
        return "<%(cls)s status=%(status)d type=%(type)s length=%(len)s>" % {
            'cls': self.__class__.__name__,
            'status': self.status,
            'len': self.headers.get('Content-Length'),
            'type': self.headers.get('Content-Type'),
        }


class Client:
    def __init__(self, hostname, conn):
        self.hostname = hostname
        self.conn = conn
    
    def build_request(self, method, path, query, headers, body=None):
        req = Request()
        req.method = method
        req.url = '%s?%s' % (path, urlencode(query)) if query else path
        req.body = body
        for hdr in headers:
            req.headers.add_header(*hdr)
        return req

    async def _request(self, request):
        writer = self.conn.writer
        start_line = '%s %s %s\r\n' % (request.method, request.url, request.version)
        writer.write(start_line.encode())
        writer.write(request.headers.as_bytes())
        if request.body:
            if not request.headers.get('Content-Length'):
                request.headers.add_header('Content-Length', str(len(request.body)))
            writer.write(request.body)
        await writer.drain()

    async def get(self, path, query=None, headers=[]):
        default_headers = [
            ('Host', self.hostname),
            ('Accept-Encoding', 'identity'),
            ('Connection', 'keep-alive'),
        ]
        
        request = self.build_request(HTTPMethod.GET, path, query, headers + default_headers)
        logger.debug('HTTP request sent to "%s": %s', self.hostname, request)
        await self._request(request)
        response = Response()
        await response.read(self.conn.reader)
        logger.debug('HTTP response received from "%s": %s', self.hostname, response)
        return response


class Server:
    def __init__(self, config, loop=None):
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.config = config
        self.server = None
        logger.debug('HTTP serivce initialized')

    async def _respond(self, writer, response):
        pass

    def build_response(self, status, content_type, content):
        resp = Response()
        resp.status = status
        resp.reason = status.name
        return resp

    async def on_request(self, request):
        response_body = request.url.encode()
        response_headers = HTTPMessage(email.policy.HTTP)
        response_headers.add_header('Content-Type', 'text/plain')
        response = Response('HTTP/1.1 200 OK', response_headers, response_body)
        return response

    async def on_error(self, status):
        resp = Response()
        return resp

    async def on_connect(self, reader, writer):
        while not writer.transport.is_closing():
            try:
                request = Request()
                await asyncio.wait_for(request.read(reader), self.timeout)
                await self._respond(writer, await self.on_request(request))
            except HttpRequestException:
                await self._respond(writer, await self.on_error(400))
                writer.transport.close()
                break
            except (TimeoutError, EOFError, asyncio.LimitOverrunError):
                writer.transport.close()
                break
            except Exception:
                await self._respond(writer, await self.on_error(500))
                writer.transport.close()
                break

    async def run(self):
        http_config = self.config['http']
        host = http_config['host']
        port = http_config['port']
        if host != '127.0.0.1' and host != 'localhost':
            logger.warn('HTTP server host %s is not safe', host)
        self.timeout = http_config['timeout']
        self.server = await asyncio.start_server(self.on_connect, host, port)
        logger.info('HTTP serivce started')

        try:
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            logger.debug('HTTP serivce interrupted')
        finally:
            self.server.close()
            #self.status = self.Status.stopped
            logger.info('HTTP serivce stopped')


async def _read_http_message(reader):
    http_header = await reader.readuntil(b'\r\n\r\n')
    fp = io.StringIO(http_header.decode())
    start_line = fp.readline()
    headers = email.parser.Parser(_class=HTTPMessage).parse(fp)
    body = None
    if headers.get('Transfer-Encoding') == 'chunked':
        body = await reader.readuntil(b'\r\n\r\n')
    else:
        content_length = headers['Content-Length']
        if content_length is not None:
            body = await reader.readexactly(int(content_length))
    return start_line, headers, body

