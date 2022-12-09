import asyncio
import base64
import io
import logging
import email
import email.policy
import mimetypes
import html
import random

from collections import namedtuple
from email.mime.multipart import MIMEMultipart
from http import HTTPStatus, HTTPMethod
from http.client import HTTPMessage
from urllib.parse import urlencode, urlsplit, parse_qs

from exceptions import HttpRequestException, HttpResponseException


HTTP_VERSION = 'HTTP/1.1'

logger = logging.getLogger(__name__)

ContentType = namedtuple('ContentType', ['media_type', 'charset', 'boundary', 'name'])

ContentDisposition = namedtuple('ContentDisposition', ['type', 'name', 'filename'])

UploadedFile = namedtuple('UploadedFile', ['filename', 'name', 'content_type', 'content'])


class FormData:
    def __init__(self):
        self.data = []
        self.boundary = self._generate_boundary()

    def _generate_boundary(self):
        alphabet = '0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'
        extra_tail = ''.join(random.sample(alphabet, 16))
        return '----WebKitFormBoundary' + extra_tail

    def get_boundary(self):
        return self.boundary

    def append(self, name, value):
        self.data.append((name, value))
        return self

    def as_bytes(self):
        with io.BytesIO() as fp:
            for item in self.data:
                key, value = item
                fp.write(b'--')
                fp.write(self.boundary.encode())
                fp.write(b'\r\n')
                fp.write(b'Content-Disposition: form-data; name="%s"\r\n' %(html.escape(key).encode(), ))
                fp.write(b'\r\n')
                fp.write(html.escape(value).encode())
                fp.write(b'\r\n')
            fp.write(b'--')
            fp.write(self.boundary.encode())
            fp.write(b'--\r\n')
            fp.seek(0)
            return fp.read(-1)


class Request:
    def get(self, name, default=None):
        if self.query and name in self.query:
            return self.query[name].pop()
        if self.form and name in self.form:
            return self.form[name].pop()
        return default

    def get_all(self, name):
        if self.query and name in self.query:
            return self.query[name]
        if self.form and name in self.form:
            return self.form[name]
        return []

    @property
    def body(self):
        return self._body

    def _parse_post_data(self, body):
        raw_content_type = self.headers.get('Conetent-Type')
        with io.BytesIO() as fp:
            fp.write(b'Content-Type: ')
            fp.write(raw_content_type.encode())
            fp.write(b'\r\n\r\n')
            fp.write(body)
            form_data = email.message_from_binary_file(
                fp, _class=HTTPMessage, policy=email.policy.HTTP).get_payload()
        if not form_data: return
        form = dict()
        files = dict()
        for item in form_data:
            content_disposition = parse_content_disposition(item.get('Content-Disposition'))
            if content_disposition.type == 'form-data' and content_disposition.name:
                if content_disposition.filename:
                    uploaded_file = parse_uploaded_file(item, content_disposition)
                    if content_disposition.name in files:
                        files[content_disposition.name].append(uploaded_file)
                    else:
                        files[content_disposition.name] = [uploaded_file]
                else:
                    if content_disposition.name in form:
                        form[content_disposition.name].append(item.get_payload())
                    else:
                        form[content_disposition.name] = [item.get_payload()]
        self.form = form
        self.files = files

    @body.setter
    def body(self, value):
        if value is None: return
        if not isinstance(value, bytes):
            raise TypeError('Response body must be bytes type, %s given' % (type(value), ))

        raw_content_type = self.headers.get('Conetent-Type')
        content_type = parse_content_type(raw_content_type)
        media_type = content_type.media_type
        charset = content_type.charset
        if media_type == 'applicaton/x-www-urlencoded':
            decoded_body = value.decode(charset) if charset \
                else value.decode(charset)
            self.form = parse_qs(decoded_body)
        elif media_type == 'multipart/form-data':
            self._parse_post_data(value)
        self._body = value

    def __init__(self):
        self.method = None
        self._url = None
        self.version = HTTP_VERSION
        self.headers = HTTPMessage(email.policy.HTTP)
        self._body = None
        self.query_string = None
        self.path = None
        self.query = None
        self.form = None
        self.files = None

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        parsed_url = urlsplit(value)
        self._url = value
        self.path = parsed_url.path
        if parsed_url.query:
            self.query_string = parsed_url.query
            self.query = parse_qs(parsed_url.query)
        else:
            self.query_string = ''
            self.query = dict

    def __repr__(self):
        if self.method is None or self.url is None:
            return '<%s>' % self.__class__.__name__
        return '<%s: %s %r>' % (
            self.__class__.__name__,
            self.method,
            self.url,
        )


class Response:
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

    def prepare_headers(self, headers):
        return headers + [
            ('Host', self.hostname),
            ('Accept-Encoding', 'identity'),
            ('Connection', 'keep-alive'),
        ]

    def build_request(self, method, path, query, headers, body=None):
        req = Request()
        req.method = method
        req.url = '%s?%s' % (path, urlencode(query)) if query else path
        for hdr in headers:
            req.headers.add_header(*hdr)
        if isinstance(body, dict):
            content_type = ('Content-Type', 'applicaton/x-www-urlencoded')
            if req.headers.get('Content-Type'):
                req.headers.replace_header(*content_type)
            else:
                req.headers.add_header(*content_type)
            body = urlencode(body).encode()
        elif isinstance(body, FormData):
            content_type = ('Content-Type', 'multipart/form-data')
            boundary = body.get_boundary()
            if req.headers.get('Content-Type'):
                req.headers.replace_header(*content_type, boundary=boundary)
            else:
                req.headers.add_header(*content_type, boundary=boundary)
            body = body.as_bytes()
        req.body = body
        return req

    async def _request(self, request):
        writer = self.conn.writer
        start_line = '%s %s %s\r\n' % (request.method, request.url, request.version)
        writer.write(start_line.encode())
        if request.body:
            if request.headers.get('Content-Length'):
                request.headers.replace_header('Content-Length', str(len(request.body)))
            else:
                request.headers.add_header('Content-Length', str(len(request.body)))
            writer.write(request.headers.as_bytes())
            writer.write(request.body)
        else:
            del request.headers['Content-Length']
            writer.write(request.headers.as_bytes())

        try:
            await writer.drain()
        except Exception as exc:
            raise HttpRequestException(str(exc))

    async def _read_response(self):
        resp = Response()
        try:
            start_line, resp.headers, resp.body = await _read_http_message(self.conn.reader)
            resp.version, status, resp.reason = start_line.split(' ', 2)
            resp.status = HTTPStatus(int(status))
        except:
            raise HttpResponseException('Invalid response')
        return resp

    async def get(self, path, query=None, headers=[]):
        request = self.build_request(HTTPMethod.GET, path, query, self.prepare_headers(headers))
        logger.debug('Request sent to "%s": %s', self.hostname, request)
        await self._request(request)
        response = await self._read_response()
        logger.debug('Response received from "%s": %s', self.hostname, response)
        return response

    async def post(self, path, query=None, headers=[], body=None):
        request = self.build_request(HTTPMethod.POST, path, query, self.prepare_headers(headers), body)
        logger.debug('Request sent to "%s": %s', self.hostname, request)
        await self._request(request)
        response = await self._read_response()
        logger.debug('Response received from "%s": %s', self.hostname, response)
        return response


class Server:
    def __init__(self, config, loop=None):
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.config = config
        self.server = None
        logger.debug('HTTP serivce initialized')

    async def _respond(self, writer, response):
        start_line = '%s %s %s\r\n' % (response.version, response.status, response.status.name)
        writer.write(start_line.encode())
        if response.body:
            if response.headers.get('Content-Length'):
                response.headers.replace_header('Content-Length', str(len(response.body)))
            else:
                response.headers.add_header('Content-Length', str(len(response.body)))
            writer.write(response.headers.as_bytes())
            writer.write(response.body)
        else:
            del response.headers['Content-Length']
            writer.write(response.headers.as_bytes())
        await writer.drain()
        return response
        
    async def _read_request(self, reader):
        req = Request()
        try:
            start_line, req.headers, req.body = await _read_http_message(reader)
            method, req.url, req.version = start_line.split(' ', 2)
            req.method = HTTPMethod(method)
        except Exception:
            raise HttpRequestException('Invalid request')
        return req

    def build_response(self, status, headers, body=None):
        resp = Response()
        resp.status = status
        resp.reason = status.name
        resp.body = body
        for hdr in headers:
            resp.headers.add_header(*hdr)
        return resp

    async def on_request(self, request):
        resp = self.build_response(HTTPStatus(200), [
            ('Content-Type', 'text/plain'),
        ], request.url.encode())
        return resp

    async def on_error(self, status):
        resp = self.build_response(HTTPStatus(status), [
            ('Connection', 'close'),
        ])
        return resp

    async def on_connect(self, reader, writer):
        peername = writer.transport.get_extra_info('peername')
        logger.debug('Connection from %s:%d' % peername)
        while not writer.transport.is_closing():
            try:
                request = await asyncio.wait_for(self._read_request(reader), self.timeout)
                logger.debug('Request received from "%s:%d": %s', *peername, request)
                response = await self._respond(writer, await self.on_request(request))
                logger.debug('Response sent to "%s:%d": %s', *peername, response)
            except HttpRequestException:
                await self._respond(writer, await self.on_error(400))
                writer.transport.close()
                break
            except (TimeoutError, EOFError, asyncio.LimitOverrunError):
                writer.transport.close()
                break
            except Exception as exc:
                await self._respond(writer, await self.on_error(500))
                writer.transport.close()
                logger.warning('Server error: %s', exc)
                break

    async def run(self):
        http_config = self.config['http']
        host = http_config['host']
        port = int(http_config['port'])
        if host != '127.0.0.1' and host != 'localhost':
            logger.warn('HTTP server host %s is not safe', host)
        self.timeout = http_config['timeout']
        self.server = await asyncio.start_server(self.on_connect, host, port)
        logger.info('HTTP serivce started')
        logger.info('HTTP server is available at http://%s:%d/', host, port)

        try:
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            logger.debug('HTTP serivce interrupted')
        finally:
            self.server.close()
            #self.status = self.Status.stopped
            logger.info('HTTP serivce stopped')


async def _readuntil(reader, sep):
    return await reader.readuntil(sep)


async def _readexactly(reader, size):
    size = int(size)
    return await reader.readexactly(size)


async def _readall(reader):
    return await reader.read()


async def _read_http_message(reader):
    http_header = await _readuntil(reader, b'\r\n\r\n')
    with io.StringIO(http_header.decode()) as fp:
        start_line = fp.readline()
        headers = email.message_from_file(fp, _class=HTTPMessage, policy=email.policy.HTTP)
    body = None
    if headers.get('Transfer-Encoding') == 'chunked':
        body = await _readuntil(reader, b'\r\n\r\n')
    else:
        content_length = headers['Content-Length']
        if content_length is not None:
            with io.BytesIO() as fp:
                body = await _readexactly(reader, content_length)
        elif headers.get('Connection') == 'close':
            body = await _readall(reader)
    return start_line, headers, body


def parse_content_type(content_type):
    if not content_type:
        return ContentType(None, None, None, None)
    directives = content_type.split(';')
    media_type = directives.pop(0).strip().lower()
    subitems = dict([[__.strip().lower() for __ in _.split('=', 1)] for _ in directives])

    return ContentType(media_type, 
                       subitems.get('charset'), 
                       subitems.get('boundary'), 
                       subitems.get('name'))


def parse_content_disposition(content_disposition):
    if not content_disposition:
        return ContentDisposition(None, None, None)
    directives = content_disposition.split(';')
    _type = directives.pop(0).strip().lower()
    subitems = dict([[__.strip().lower() for __ in _.split('=', 1)] for _ in directives])

    return ContentType(_type, 
                       subitems.get('name'),  
                       subitems.get('filename'))


def parse_uploaded_file(message, content_disposition=None):
    if content_disposition is None:
        content_disposition = parse_content_disposition(message.get('Content-Disposition'))
    name = html.unescape(content_disposition.name)
    filename = html.unescape(content_disposition.filename)
    encoding = message.get('Content-Transfer-Encoding')
    content_type = parse_content_type(message.get('Conent-Type'))
    content = message.get_payload()
    if encoding == 'base64':
        content = base64.b64decode(content)
    else:
        content = content.encode()
    return UploadedFile(filename, name, content_type, content)
