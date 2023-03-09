import asyncio
import base64
import logging
import struct
import functools
import enum
import time
import math

from importlib import resources

import maxminddb
import dnslib

from . import https
from . import middlewares
from . import version
from .config import DnsUpstream, HttpsUpstream, TlsUpstream
from .pool import Pool
from .exceptions import *
from .upstream import UpstreamCollection
from .proxy import parse_proxy
from .helpers import s_addr, Scheme


logger = logging.getLogger(__name__)


TEST_DOMAIN = 'www.google.com'


class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.need_restart = False

    def datagram_received(self, data, addr):
        self.server.on_request(self.transport, data, addr)

    def error_received(self, exc):
        if isinstance(exc, OSError):
            logger.debug(exc)
        else:
            logger.info('DNS server error received: %s', exc)
        self.need_restart = True
        self.transport.abort()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if self.need_restart:
            self.need_restart = False
            self.server.on_error_reset(self.transport)

    def connection_made(self, transport):
        self.transport = transport


class QueryProtocol(asyncio.DatagramProtocol):
    def __init__(self, data, response):
        super().__init__()
        self.data = data
        self.response = response

    def connection_made(self, transport):
        self.transport = transport
        transport.sendto(self.data)

    def datagram_received(self, data, addr):
        self.transport.close()
        self.response.set_result(data)

    def error_received(self, exc):
        logger.error('DNS query error: %s', exc)


class Server:
    class Status(enum.Enum):
        INITIALIZED = enum.auto()
        START_PEDDING = enum.auto()
        RUNNING = enum.auto()
        RESTART_PEDDING = enum.auto()
        STOP_PEDDING = enum.auto()
        STOPPED = enum.auto()

    def __init__(self, config, loop=None):
        self.config = config
        self.pool = Pool()
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.restart_event = asyncio.Event()
        self.status = self.Status.INITIALIZED
        self.tasks = []
        self.transports = []
        logger.debug('DNS serivce initialized')

    async def bootstrap(self):
        logger.debug('DNS service bootstrapping')

        if self.test_geoip('114.114.114.114', 'cn'):
            logger.info('Test GeoIP2 database passed')
        else:
            logger.warning('Test GeoIP2 database failed')

        self.local_addrs = self.config['listen']
        self.timeout_sec = self.config['timeout'] / 1000
        self.upstreams = UpstreamCollection(self.config['upstreams'], 
                                            self.config['secure'],
                                            self.config['ipv6'])
        self.proxy = self.config['proxy']
        if self.proxy:
            logger.info('Using proxy %s', self.proxy)
        bootstrap_upstreams = []
        hostname_upstreams = []
        named_upstreams = dict()

        for upstream in self.upstreams.all():
            if upstream.host:
                bootstrap_upstreams.append(upstream)
            else:
                hostname_upstreams.append(upstream)

            if upstream.name:
                if upstream.name in named_upstreams:
                    raise InvalidConfig('Duplicated upstream name "%s"' % (upstream.name, ))
                named_upstreams[upstream.name] = upstream

        async def resolve_upstream_hostname(hostname_upstream, bootstrap_upstreams):
            request = dnslib.DNSRecord.question(hostname_upstream.hostname)
            response = await self.handle(request, upstreams=bootstrap_upstreams)
            if not response or response.header.a == 0:
                logger.warning('Failed to resolve upstream domain "%s"', hostname_upstream.hostname)
                hostname_upstream.disable = True
            else:
                hostname_upstream.host = str(response.rr[0].rdata)

        await asyncio.gather(*[
            resolve_upstream_hostname(hostname_upstream, bootstrap_upstreams) \
                for hostname_upstream in hostname_upstreams
        ])

        await self.test_all_upstreams(TEST_DOMAIN)
        return True

    async def test_upstream(self, upstream, hostname):
        request = dnslib.DNSRecord.question(hostname)
        start_counter = time.perf_counter()
        response = await self.handle(request, upstreams=[upstream])
        elapsed_time_sec = time.perf_counter() - start_counter
        if not response or response.header.a == 0:
            upstream.disable = True
            upstream.priority = -1
            logger.warning('Test upstream %s failed', upstream.name)
            return False
        timeout_sec = self._get_timeout(upstream)
        upstream.priority = int(max(0, timeout_sec - elapsed_time_sec) / timeout_sec * 1000)
        upstream.disable = False
        logger.info('Test upstream %s passed, responding speed: %d', upstream.name, upstream.priority)
        return True

    async def test_all_upstreams(self, hostname, include_disabled=False):
        queries = [
            self.test_upstream(upstream, hostname) 
            for upstream in self.upstreams.all() 
            if include_disabled or not upstream.disable
        ]
        await asyncio.gather(*queries)
        self.upstreams.sort()
        primary_upstream = self.upstreams.primary
        if primary_upstream.disable:
            raise NetworkError('No available upstream server')
        logger.info('Primary DNS is %s', primary_upstream.name)

    def create_task(self, coro, name=None, context=None):
        task = self.loop.create_task(coro, name=name, context=context)
        self.tasks.append(task)
        task.add_done_callback(lambda _: self.remove_task(task))
        return task

    def create_scheduled_task(self, coro, timer, name=None, context=None):
        async def _task():
            async for i in timer:
                logger.debug('Schedule task "%s" repeat times %d' % (name, i))
                await coro()

        return self.create_task(_task(), name, context)

    def remove_task(self, task):
        self.tasks.remove(task)

    def _get_proxy(self, upstream, **kwargs):
        if 'proxy' in kwargs:
            return parse_proxy(kwargs['proxy'])
        elif upstream.proxy:
            return upstream.proxy
        return self.proxy

    def _create_middlewares(self):
        wrapped = self
        names = self.config['middlewares']
        for name in names:
            try:
                wrapped = middlewares.create_middleware(
                    name, wrapped, self.config.get(name)
                )
            except TypeError as exc:
                raise InvalidConfig(exc)
            logger.info('%s loaded', wrapped.__class__.__name__)
        return wrapped

    async def _resolve_by_dns(self, query, upstream, proxy):
        response_future = self.loop.create_future()
        upstream_addr = upstream.to_addr()

        if proxy and proxy.udp_tunnel_enabled():
            try:
                conn = await self.pool.connect(
                    upstream.host, 
                    upstream.port, 
                    Scheme.UDP, 
                    proxy
                )
            except ConnectionError as exc:
                logger.warning('Failed to connect to proxy %s: %s', proxy.hostname, exc)
                return
            transport, _ = await self.loop.create_datagram_endpoint(
                lambda: QueryProtocol(
                    conn.udp_tunnel.pack(query, upstream_addr), 
                    response_future
                ),
                remote_addr=conn.udp_tunnel.addr
            )
            try:
                response = conn.udp_tunnel.parse(
                    await response_future, 
                    upstream_addr
                )
            finally:
                transport.close()
            return response

        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: QueryProtocol(query, response_future),
            remote_addr=upstream_addr
        )
        try:
            response = await response_future
        finally:
            transport.close()
        return response

    async def _resolve_by_https(self, query, upstream, proxy):
        try:
            with await self.pool.connect(
                upstream.host, 
                upstream.port, 
                Scheme.TLS, 
                proxy
            ) as conn:
                q = base64.b64encode(query).decode().rstrip('=')
                return (await https.Client(upstream.hostname, conn).get(
                    upstream.path,
                    {'dns': q}, 
                    [("Content-type", "application/dns-message")]
                )).body
        except HttpException as exc:
            logger.warning('HTTP exception from %s: %s', upstream.name, exc)
        except ConnectionError as exc:
            logger.warning('Failed to connect to %s: %s', upstream.name, exc)

    async def _resolve_by_tls(self, query, upstream, proxy):
        try:
            with await self.pool.connect(
                upstream.host, 
                upstream.port, 
                Scheme.TLS, 
                proxy
            ) as conn:
                query_size = struct.pack('!H', len(query))
                conn.writer.write(query_size + query)
                await conn.writer.drain()
                response_head = await conn.reader.readexactly(2)
                response_size = struct.unpack('!H', response_head)[0]
                return await conn.reader.readexactly(response_size)
        except asyncio.exceptions.IncompleteReadError:
            logger.error('Failed to read data from %s', upstream.name)
        except ConnectionError as exc:
            logger.warning('Failed to connect to %s: %s', upstream.name, exc)

    async def fetch(self, url, **kwargs):
        return await https.fetch(url, self.handle, 
                                      self.pool, 
                                      self.proxy,
                                      **kwargs)

    def _get_timeout(self, upstream):
        return self.timeout_sec if upstream.timeout_sec is None else upstream.timeout_sec

    def _get_upstreams(self, kwargs):
        customized_upstreams = []
        if 'upstreams' in kwargs:
            customized_upstreams.extend(kwargs['upstreams'])
        if 'upstream' in kwargs:
            customized_upstreams.append(kwargs['upstream'])
        if 'upstream_name' in kwargs:
            upstream_name = kwargs['upstream_name']
            if upstream_name in self.upstreams:
                customized_upstreams.append(self.upstreams[upstream_name])
            else:
                logger.warning('Upstream name %s not defined', upstream_name)
        if 'upstream_group' in kwargs:
            upstream_group = kwargs['upstream_group']
            if self.upstreams.has_group(upstream_group):
                customized_upstreams.extend(self.upstreams.group(upstream_group))
            else:
                logger.warning('Upstream group %s not defined', upstream_group)
        if customized_upstreams:
            kwargs['customized_upstreams'] = True
            return customized_upstreams
        return self.upstreams.sorted

    async def handle(self, request, **kwargs):
        logger.debug('DNS query:\n%s', request)
        data = request.pack()

        for upstream in self._get_upstreams(kwargs):
            proxy = self._get_proxy(upstream, **kwargs)
            if upstream.disable and 'customized_upstreams' not in kwargs:
                continue
            if isinstance(upstream, DnsUpstream):
                resolver = self._resolve_by_dns
            elif isinstance(upstream, HttpsUpstream):
                resolver = self._resolve_by_https
            elif isinstance(upstream, TlsUpstream):
                resolver = self._resolve_by_tls
            else:
                raise TypeError('Invalid upstream type: %s' % (type(upstream).__name__, ))
            if 'traceback' in kwargs:
                kwargs['traceback'].append(upstream.name)

            try:
                upstream.usage += 1
                response_data = await asyncio.wait_for(
                    asyncio.shield(resolver(data, upstream, proxy)), 
                    self._get_timeout(upstream)
                )
                if response_data is None:
                    raise EmptyValueError('Empty response data received')
                try:
                    response = dnslib.DNSRecord.parse(response_data)
                except dnslib.DNSError:
                    raise UnexpectedValueError('Invalid response data received')
                if request.header.id != response.header.id:
                    raise UnexpectedValueError('Response id does not match')
                upstream.success += 1
                logger.debug('DNS response:\n%s', response)
                return response
            except ValueError:
                logger.warning('Failed to resolve by upstream server %s', upstream.name)
            except (TimeoutError, asyncio.exceptions.TimeoutError):
                logger.info('Upstream server %s response timeout', upstream.name)

    async def _handle(self, request):
        resolver = self.middlewares if self.middlewares else self
        if request.header.q > 1:
            coroutines = []
            for q in request.questions:
                _req = request.truncate()
                _req.add_question(q)
                coroutines.append(resolver.handle(_req))
            response = dnslib.DNSRecord(dnslib.DNSHeader(id=request.header.id,
                                           bitmap=request.header.bitmap,
                                           qr=1, ra=1, aa=1),
                                questions=request.questions)
            for _resp in await asyncio.gather(*coroutines):
                if _resp and _resp.header.a > 0:
                    response.add_answer(_resp.a)
            return response
        return await resolver.handle(request)

    def on_response(self, transport, request, addr, future):
        response = future.result()
        if response is None:
            logger.info('Failed to resolve domain name "%s", upstream servers are unreachable', request.q.qname)
            return

        logger.debug('Send response to %s\n%s', s_addr(addr), response)
        try:
            transport.sendto(response.pack(), addr)
        except Exception:
            logger.debug('Failed to send data to %s', s_addr(addr))

    def on_request(self, transport, data, addr):
        request = dnslib.DNSRecord.parse(data)
        logger.debug('Received request from %s\n%s', s_addr(addr), request)
        task = self.loop.create_task(self._handle(request))
        task.add_done_callback(functools.partial(self.on_response, transport, request, addr))

    def restart(self):
        self.status = self.Status.RESTART_PEDDING
        logger.info('Restarting service')
        
        from .cli import parse_arguments
        from .config import Config
        self.config = Config.load(parse_arguments())

        self.restart_event.set()

    def on_error_reset(self, transport):
        self.transports.remove(transport)
        sockname = transport.get_extra_info('sockname')
        async def reset(sockname):
            transport, _ = await self.loop.create_datagram_endpoint(
                lambda: ServerProtocol(self),
                local_addr=sockname
            )
            self.transports.append(transport) 
        return self.loop.create_task(reset(sockname))

    async def run(self):
        self.status = self.Status.START_PEDDING
        await self._run()
        while self.status == self.Status.RESTART_PEDDING:
            self.restart_event.clear()
            await self._run()

    async def _run(self):
        self.middlewares = self._create_middlewares()
        try:
            if not await self.middlewares.bootstrap():
                logger.error('Failed to bootstrap')
                return

            for local_addr in self.local_addrs:
                try:
                    transport, _ = await self.loop.create_datagram_endpoint(
                        lambda: ServerProtocol(self),
                        local_addr=local_addr
                    )
                    self.transports.append(transport)
                    logger.info('DNS service listening on %s', s_addr(local_addr))
                except OSError as exc:
                    logger.error('Failed to start DNS service: %s', exc)
                    return

            self.status = self.Status.RUNNING
            logger.info('DNS serivce started')

            try:
                await self.restart_event.wait()
            except asyncio.CancelledError:
                logger.debug('DNS serivce interrupted')
            finally:
                if self.status == self.Status.RUNNING:
                    self.status = self.Status.STOPPED
                    logger.info('DNS serivce stopped')
        finally:
            for transport in self.transports:
                transport.close()
            self.pool.dispose()

    def open_geoip(self):
        geoip_db = self.config.get('geoip')
        if geoip_db is not None:
            return maxminddb.open_database(geoip_db)

        with resources.open_binary(__package__, 'geoip') as geoip_db:
            return maxminddb.open_database(geoip_db, maxminddb.MODE_FD)
    
    def test_geoip(self, ip, country):
        result = self.open_geoip().get(ip)
        _country = result['country']['iso_code'] if result else None
        return country.upper() == _country

    async def handle_http_request(self, request):
        match request.method, request.path:
            case https.HTTPMethod.GET, '/':
                return https.Response(body='Dnspooh is working')
            case https.HTTPMethod.GET, '/status':
                return https.response_json_result(self.status.name)
            case https.HTTPMethod.POST, '/restart':
                return https.response_json_result(self.restart())
            case https.HTTPMethod.GET, '/version':
                return https.response_json_result(version.__version__)
            case https.HTTPMethod.GET, '/upstreams':
                return https.response_json_result({
                    'upstreams': self.upstreams,
                    'primary': self.upstreams.primary,
                })
            case https.HTTPMethod.POST, '/upstreams/primary':
                return self._handle_select_primary_upstream(request)
            case https.HTTPMethod.POST, '/upstreams/test':
                return await self._handle_test_upstream(request)
            case https.HTTPMethod.POST, '/upstreams/test-all':
                return await self._handle_test_all_upstream()
            case https.HTTPMethod.GET, '/pool':
                return https.response_json_result(self.pool)
            case https.HTTPMethod.GET, '/config':
                return https.response_json_result(self.config)
            case https.HTTPMethod.GET, '/logs':
                return self._handle_query_access_log(request)
            case https.HTTPMethod.POST, '/dns-query':
                return await self._handle_dns_query(request)
            case https.HTTPMethod.POST, '/geoip2-query':
                return await self._handle_geoip2_query(request)
        raise HttpNotFound()
    
    def _handle_query_access_log(self, request):
        log_middleware = self.middlewares.get_component('log')
        if not isinstance(log_middleware, middlewares.LogMiddleware):
            return https.response_json_error('The log middleware is not enabled')

        page = request.get_int('page', 1)
        total = log_middleware.query_total()
        page_size = middlewares.log.QUERY_PAGE_SIZE
        return https.response_json_result({
            'total': total,
            'page': {
                'current': page,
                'size': page_size,
                'count': math.ceil(total / page_size),
            },
            'logs': log_middleware.query_dataset(page),
        })

    @https.json_handler
    def _handle_select_primary_upstream(self, name):
        self.upstreams.select(name)
        return https.response_json_result(True)

    @https.async_json_handler
    async def _handle_test_upstream(self, name):
        if name not in self.upstreams:
            return https.JsonResponse(https.JSONError.ILLEGAL_PARAM, 
                                      https.HTTPStatus.BAD_REQUEST) 
        return https.response_json_result(await self.test_upstream(self.upstreams[name], TEST_DOMAIN))

    @https.async_json_handler
    async def _handle_dns_query(self, domain):
        request = dnslib.DNSRecord.question(domain)
        response = await self.handle(request)
        if response is None:
            return https.response_json_error('Failed to resolve domain name %s' % domain)
        return https.response_json_result(str(response))

    @https.async_json_handler
    async def _handle_geoip2_query(self, ip):
        try:
            result = self.open_geoip().get(ip)
        except ValueError as exc:
            return https.response_json_error(exc)
        return https.response_json_result(result)

    async def _handle_test_all_upstream(self):
        await self.test_all_upstreams(TEST_DOMAIN, True)
        return https.response_json_result(True)
