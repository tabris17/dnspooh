import asyncio
import io
import logging
import email.parser
import email.policy

from http import HTTPStatus, HTTPMethod
from http.client import HTTPMessage

from exceptions import HttpException


HTTP_VERSION = 'HTTP/1.1'

logger = logging.getLogger(__name__)


class HttpProtocol:
    def __init__(self, start_line, headers=None, body=None):
        try:
            self.start_line = start_line
            self.headers = HTTPMessage(email.policy.HTTP) if headers is None else headers
            self.body = body
            if body and not headers.get('Content-Length'):
                headers.add_header('Content-Length', str(len(body)))
            self.parse_start_line(start_line)
        except Exception as exc:
            raise HttpException(exc)

    def parse_start_line(self, start_line):
        raise NotImplementedError()

    async def sendto(self, writer):
        writer.write(self.as_bytes())
        await writer.drain()

    def as_bytes(self):
        try:
            data = io.BytesIO()
            data.write(self.start_line.encode())
            data.write(b'\r\n')
            data.write(self.headers.as_bytes()) 
            if self.body: data.write(self.body)
            return data.getvalue()
        except Exception as exc:
            raise HttpException(exc)

    def __bytes__(self):
        return self.as_bytes()

    def __repr__(self):
        return self.as_bytes().decode()

    @classmethod
    async def read_from(cls, reader):
        raw_headers = await reader.readuntil(b'\r\n\r\n')
        fp = io.StringIO(raw_headers.decode())
        start_line = fp.readline()
        headers = email.parser.Parser(_class=HTTPMessage).parse(fp)
        body = None
        if headers.get('Transfer-Encoding') == 'chunked':
            body = await reader.readuntil(b'\r\n\r\n')
        else:
            content_length = headers['Content-Length']
            if content_length is not None:
                try:
                    content_length = int(content_length)
                except TypeError:
                    raise HttpException('Invalid content length "%s"' % (content_length, ))
                body = await reader.readexactly(content_length)

        return cls(start_line, headers, body)


class Request(HttpProtocol):
    def parse_start_line(self, start_line):
        method, url, version = start_line.split(' ', 2)
        self.method = HTTPMethod(method)
        self.url = url
        self.version = version


class Response(HttpProtocol):
    def parse_start_line(self, start_line):
        version, status_code, status_text = start_line.split(' ', 2)
        self.status = HTTPStatus(int(status_code))
        self.status_text = status_text
        self.version = version


class Client:
    def __init__(self, conn):
        self.conn = conn

    async def get(self, url, hostname, headers=[]):
        default_headers = [
            ('Host', hostname),
            ('Accept-Encoding', 'identity'),
            ('Connection', 'keep-alive'),
        ]
        parsed_headers = HTTPMessage(email.policy.HTTP)
        for header in default_headers + headers:
            parsed_headers.add_header(*header)
        request = Request('%s %s %s' % (HTTPMethod.GET, url, HTTP_VERSION), parsed_headers)
        logger.debug('HTTP request:\n%s', request)
        await request.sendto(self.conn.writer)
        response = await Response.read_from(self.conn.reader)
        logger.debug('HTTP response:\n%s', response)
        return response


class Server:
    def __init__(self, config, loop=None):
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.config = config
        self.server = None
        logger.debug('HTTP serivce initialized')

    async def on_request(self, reader, writer):
        while not writer.transport.is_closing():
            try:
                request = await Request.read_from(reader)
                response_body = request.url.encode()
                response_headers = HTTPMessage(email.policy.HTTP)
                response_headers.add_header('Content-Type', 'text/plain')
                response = Response('HTTP/1.1 200 OK', response_headers, response_body)
                await response.sendto(writer)
            except HttpException as exc:
                response = Response('HTTP/1.1 400 Bad Request')
                await response.sendto(writer)
                writer.transport.close()
                break

    async def run(self):
        http_config = self.config['http']
        host = http_config['host']
        port = http_config['port']
        if host != '127.0.0.1' and host != 'localhost':
            logger.warn('HTTP server host %s is not safe', host)
        self.server = await asyncio.start_server(self.on_request, host, port)
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
