import asyncio
import base64
import io
import json
import logging
import enum
import email
import email.policy
import mimetypes
import html
import pathlib
import random
import ipaddress
import dnslib

from collections import namedtuple
from http import HTTPStatus
from http.client import HTTPMessage
from urllib.parse import urlencode, urlsplit, parse_qs, quote

from .scheme import Scheme
from .exceptions import HttpException, HttpHeaderTooLarge, HttpPayloadTooLarge, HttpNotFound, InvalidConfig
from .helpers import s_addr


HTTP_VERSION = 'HTTP/1.1'

DEFAULT_HTTP_PORT = 80

DEFAULT_HTTPS_PORT = 443


logger = logging.getLogger(__name__)

ContentType = namedtuple('ContentType', ['media_type', 'charset', 'boundary', 'name'])

ContentDisposition = namedtuple('ContentDisposition', ['type', 'name', 'filename'])

UploadedFile = namedtuple('UploadedFile', ['filename', 'name', 'content_type', 'content'])


class HTTPMethod(str, enum.Enum):
    CONNECT = 'CONNECT'
    DELETE = 'DELETE'
    GET = 'GET'
    HEAD = 'HEAD'
    OPTIONS = 'OPTIONS'
    PATCH = 'PATCH'
    POST = 'POST'
    PUT = 'PUT'
    TRACE = 'TRACE'

    def __str__(self):
        return self.value


class HttpMessage(HTTPMessage):
    def get_content_maintype(self):
        maintype = super().get_content_maintype()
        if maintype == 'multipart':
            return ''
        return maintype

    def set_header(self, name, value, **params):
        if self.get(name):
            del self[name]
        return self.add_header(name, str(value), **params)

    def is_closing(self):
        return self.get('Connection', '').lower() == 'close'


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
                fp, _class=HttpMessage, policy=email.policy.HTTP).get_payload()
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
        self.headers = HttpMessage(email.policy.HTTP)
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
        self.path = quote(parsed_url.path)
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
    def __init__(self, status=200):
        self._status = HTTPStatus(status)
        self.is_sent = False
        self.reason = self._status.name
        self.version = HTTP_VERSION
        self.headers = HttpMessage(email.policy.HTTP)
        self.body = None

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        if not isinstance(value, HTTPStatus):
            value = HTTPStatus(value)
        self._status = value
        self.reason = value.name

    def __repr__(self):
        return "<%(cls)s status=%(status)d type=%(type)s length=%(len)s>" % {
            'cls': self.__class__.__name__,
            'status': self.status,
            'len': len(self.body),
            'type': self.headers.get('Content-Type'),
        }


class FileResponse(Response):
    def __init__(self, file):
        super().__init__()
        self.file = file

    @property
    def size(self):
        return self.file.stat().st_size

    def __repr__(self):
        return "<%(cls)s status=%(status)d type=%(type)s length=%(len)s>" % {
            'cls': self.__class__.__name__,
            'status': self.status,
            'len': self.size,
            'type': self.headers.get('Content-Type'),
        }


class JsonResponse(Response):
    def __init__(self, payload):
        super().__init__(200)
        self.body = json.dumps(payload).encode()
        self.headers.add_header('Content-Type', 'application/json', charset='utf-8')

    def __repr__(self):
        return "<%(cls)s status=%(status)d type=%(type)s length=%(len)s>" % {
            'cls': self.__class__.__name__,
            'status': self.status,
            'len': len(self.body),
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
            req.headers.set_header('Content-Type', 'application/x-www-form-urlencoded')
            body = urlencode(body).encode()
        elif isinstance(body, FormData):
            req.headers.set_header('Content-Type', 'multipart/form-data', boundary=body.get_boundary())
            body = body.as_bytes()
        req.body = body
        return req

    async def _request(self, request):
        writer = self.conn.writer
        start_line = '%s %s %s\r\n' % (request.method, request.url, request.version)
        writer.write(start_line.encode())
        if request.body:
            request.headers.set_header('Content-Length', len(request.body))
            writer.write(request.headers.as_bytes())
            writer.write(request.body)
        else:
            del request.headers['Content-Length']
            writer.write(request.headers.as_bytes())

        try:
            await writer.drain()
        except Exception as exc:
            raise HttpException(str(exc))

    async def _read_response(self):
        resp = Response()
        try:
            start_line, resp.headers, resp.body = await _read_http_message(self.conn.reader)
            resp.version, status, resp.reason = start_line.split(' ', 2)
            resp.status = HTTPStatus(int(status))
        except (HttpException, asyncio.CancelledError) as exc:
            raise exc
        except:
            raise HttpException('Invalid response')
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
    MAX_REQUEST_SIZE = 1024 * 1024 * 16

    DEFAULT_FILES = ['index.html', 'index.htm', 'default.htm', 'default.html']

    def __init__(self, config, handler=None, loop=None):
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.config = config
        self._request_handler = self._create_request_handler(handler)
        self._server = None
        logger.debug('HTTP serivce initialized')
    
    def _create_request_handler(self, handler):
        if hasattr(handler, 'handle'):
            async def _handler(req):
                return await handler.handle(req)
        elif callable(handler):
            async def _handler(req):
                return await handler(req)
        else:
            async def _handler(req):
                return await self.on_error(404)
        return _handler

    async def _respond(self, writer, response):
        try:
            response.headers.add_header('Server', __package__)
            start_line = '%s %d %s\r\n' % (response.version, response.status.value, response.status.phrase)
            writer.write(start_line.encode())
            if isinstance(response, FileResponse):
                ctype, charset = mimetypes.guess_type(response.file)
                kwargs = {} if charset is None else {'charset': charset}
                response.headers.set_header(
                    'Content-Type', 
                    'application/octet-stream' if ctype is None else ctype,
                    **kwargs
                )
                with response.file.open('rb') as fp:
                    response.headers.set_header('Content-Length', response.size)
                    writer.write(response.headers.as_bytes())
                    await writer.drain()
                    await self.loop.sendfile(writer.transport, fp)
                response.is_sent = True
                return response
            elif response.body:
                response.headers.set_header('Content-Length', len(response.body))
                writer.write(response.headers.as_bytes())
                writer.write(response.body)
            else:
                del response.headers['Content-Length']
                writer.write(response.headers.as_bytes())
            await writer.drain()
            response.is_sent = True
        except asyncio.CancelledError:
            raise
        except:
            raise IOError('Response begin sending and an error occurred')
        finally:
            if response.headers.is_closing():
                writer.transport.abort()
        return response
        
    async def _read_request(self, reader):
        req = Request()
        try:
            start_line, req.headers, req.body = await _read_http_message(reader, self.MAX_REQUEST_SIZE)
            method, req.url, req.version = start_line.split(' ', 2)
            req.method = HTTPMethod(method)
        except (HttpException, asyncio.CancelledError):
            raise
        except:
            raise HttpException('Invalid request')
        return req

    def _attempt_static_file(self, path):
        if not self.static_files:
            return False

        file_path = self.static_files.joinpath('.' + path)
        if file_path.is_dir():
            for default_file in self.DEFAULT_FILES:
                file_path = file_path.joinpath(default_file)
                if file_path.exists():
                    return file_path
        elif file_path.exists():
            return file_path

        return False

    async def on_request(self, request):
        static_file = self._attempt_static_file(request.path)
        if static_file:
            return FileResponse(static_file)
        return await (self._request_handler)(request)

    async def on_error(self, status, body=None):
        resp = Response(status)
        resp.headers.add_header('Connection', 'close')
        resp.body = body
        return resp

    async def on_connect(self, reader, writer):
        peername = writer.transport.get_extra_info('peername')
        logger.debug('Connection from %s', s_addr(peername))
        try:
            while not writer.transport.is_closing():
                try:
                    request = await asyncio.wait_for(self._read_request(reader), self.timeout_sec)
                    logger.debug('Request received from "%s": %s', s_addr(peername), request)
                except HttpException as exc:
                    await self._respond(writer, await self.on_error(400))
                    break
                except Exception as exc:
                    await self._respond(writer, await self.on_error(500))
                    logger.warning('Server error on request: %s', exc)
                    break

                try:
                    response = await self._respond(writer, await self.on_request(request))
                    logger.debug('Response sent to "%s": %s', s_addr(peername), response)
                except Exception as exc:
                    if response.is_sent:
                        writer.transport.abort()
                    else:
                        await self._respond(writer, await self.on_error(500))
                    logger.warning('Server error on response: %s', exc)
                    break
        except (TimeoutError, asyncio.exceptions.TimeoutError, EOFError, IOError):
            writer.transport.abort()
        except asyncio.CancelledError:
            logger.debug('Connection from %s has been cancelled', s_addr(peername))

    async def run(self):
        http_config = self.config['http']
        if http_config.get('disable'):
            return
        static_files = http_config.get('static_files')
        if static_files:
            static_files_path = pathlib.Path(http_config['static_files'])
            if not static_files_path.is_dir():
                raise InvalidConfig('%s is not a directory' % static_files_path)
            self.static_files = static_files_path
        else:
            self.static_files = None
        host = http_config['host']
        port = int(http_config['port'])
        if host != '127.0.0.1' and host != 'localhost':
            logger.warn('HTTP server host %s is not safe', host)
        self.timeout_sec = http_config['timeout'] / 1000
        self._server = await asyncio.start_server(self.on_connect, host, port)
        logger.info('HTTP serivce started')
        logger.info('HTTP server is available at http://%s:%d/', host, port)

        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.debug('HTTP serivce interrupted')
        finally:
            self._server.close()
            logger.info('HTTP serivce stopped')


async def _read_http_message(reader, max_body=None):
    try:
        http_header = await reader.readuntil(b'\r\n\r\n')
    except asyncio.exceptions.LimitOverrunError as exc:
        raise HttpHeaderTooLarge(exc)
    with io.StringIO(http_header.decode()) as fp:
        start_line = fp.readline()
        headers = email.message_from_file(fp, _class=HttpMessage, policy=email.policy.HTTP)
    body = None
    if headers.get('Transfer-Encoding') == 'chunked':
        with io.BytesIO() as fp:
            while True:
                chunk_len_ln = await reader.readuntil(b'\r\n')
                chunk_len = int(chunk_len_ln[:-2].decode(), 16)
                if chunk_len == 0: break
                fp.write(await reader.readexactly(chunk_len))
                if b'\r\n' != await reader.readexactly(2):
                    raise HttpException('Chunked encoding error, missing CRLF')
                if max_body and fp.tell() > max_body:
                    raise HttpPayloadTooLarge('The size of payload is greater than %d', max_body)
            fp.seek(0)
            body = fp.read(-1)
    else:
        content_length = headers['Content-Length']
        if content_length is not None:
            with io.BytesIO() as fp:
                body = await reader.readexactly(int(content_length))
        elif headers.get('Connection') == 'close':
            body = await reader.read()
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


async def fetch(url, resolver, pool, proxy=None, **kwargs):
    parsed_url = urlsplit(url)
    hostname = parsed_url.hostname
    if parsed_url.scheme == 'http':
        scheme = Scheme.tcp
        port = parsed_url.port if parsed_url.port else DEFAULT_HTTP_PORT
    elif parsed_url.scheme == 'https':
        scheme = Scheme.tls
        port = parsed_url.port if parsed_url.port else DEFAULT_HTTPS_PORT
    else:
        raise ValueError('Invalid url scheme %s' % (parsed_url.scheme, ))
    try:
        ipaddress.ip_address(hostname)
        host = hostname
    except ValueError:
        dns_request = dnslib.DNSRecord.question(hostname)
        dns_response = await resolver(dns_request)
        if not dns_response or dns_response.header.a == 0:
            raise HttpException('Could not resolve domain %s' % (hostname, ))
        host = str(dns_response.rr[0].rdata)
    if 'method' in kwargs:
        method = HTTPMethod(kwargs['method'])
    else:
        method = HTTPMethod.GET
    if method not in (HTTPMethod.GET, HTTPMethod.POST):
        raise ValueError('Unsupported http method %s' % (method.name, ))
    url_path = quote(parsed_url.path)
    if parsed_url.query:
        url_path = '%s?%s' % (url_path, parsed_url.query)
    headers = kwargs.get('headers', [])

    with await pool.connect(host, port, scheme, proxy, pooled=False) as conn:
        if method == HTTPMethod.GET:
            return await Client(hostname, conn).get(url_path, headers=headers)
        else:
            body = kwargs.get('body')
            return await Client(hostname, conn).post(url_path, headers=headers, body=body)
