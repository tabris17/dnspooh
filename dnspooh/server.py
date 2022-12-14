import asyncio
import base64
import logging
import struct
import functools
import enum
import time

import maxminddb

from dnslib import DNSRecord, DNSError, DNSHeader

import https
import middlewares
from config import DnsUpstream, HttpsUpstream, TlsUpstream
from pool import Pool
from scheme import Scheme
from exceptions import EmptyValueError, UnexpectedValueError, HttpException
from stats import Stats
from upstream import UpstreamCollection


logger = logging.getLogger(__name__)


class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.server = server
        self.need_restart = False

    def datagram_received(self, data, addr):
        self.server.on_request(data, addr)

    def error_received(self, exc):
        logger.error('DNS server error: %s', exc)
        self.need_restart = True
        self.server.transport.close()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if self.need_restart:
            self.need_restart = False
            self.server.on_error_restart()


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
        initialized = enum.auto()
        start_pedding = enum.auto()
        running = enum.auto()
        restart_pedding = enum.auto()
        stop_pedding = enum.auto()
        stopped = enum.auto()

    def __init__(self, config, loop=None):
        self.config = config
        self.pool = Pool()
        self.loop = asyncio.get_running_loop() if loop is None else loop
        self.abort_event = asyncio.Event()
        self.middlewares = self._create_middlewares()
        self.transport = None
        self.stats = Stats(config['stats.max_size'])
        self.status = self.Status.initialized
        self.tasks = []
        logger.debug('DNS serivce initialized')

    async def bootstrap(self):
        logger.info('DNS service bootstrapping')
        self.host = self.config['host']
        self.port = self.config['port']
        self.timeout = self.config['timeout']
        self.upstreams = UpstreamCollection(self.config['upstreams'], 
                                            self.config['secure'])
        self.proxy = self.config['proxy']
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
                    raise RuntimeError('Duplicated upstream name "%s"' % (upstream.name, ))
                named_upstreams[upstream.name] = upstream

        async def resolve_upstream_hostname(hostname_upstream, bootstrap_upstreams):
            request = DNSRecord.question(hostname_upstream.hostname)
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

        await self.test_upstreams('google.com')
        return True

    async def test_upstreams(self, hostname):
        request = DNSRecord.question(hostname)
        async def test_upstream(upstream):
            start_counter = time.perf_counter()
            response = await self.handle(request, upstreams=[upstream])
            cost_time = time.perf_counter() - start_counter
            if not response or response.header.a == 0:
                upstream.disable = True
                upstream.priority = -1
                logger.warning('Test upstream %s error', upstream.name)
            else:
                timeout = self._get_timeout(upstream)
                upstream.priority = int((timeout - cost_time) / timeout * 1000)
                logger.info('Test upstream %s OK', upstream.name)

        await asyncio.gather(*[test_upstream(_) for _ in self.upstreams.all() if not _.disable])
        self.upstreams.sort()
        logger.info('Primary DNS is %s', self.upstreams.primary.name)

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

    def _get_proxy(self, upstream):
        return self.proxy if upstream.proxy is None \
            else upstream.proxy

    def _create_middlewares(self):
        wrapped = self
        names = self.config['middlewares']
        for name in names:
            wrapped = middlewares.create_middleware(
                name, wrapped, self.config.get(name)
            )
        return wrapped

    async def _resolve_by_dns(self, query, upstream):
        response_future = self.loop.create_future()
        upstream_addr = upstream.to_addr()

        proxy = self._get_proxy(upstream)
        if proxy and proxy.udp_tunnel_enabled():
            try:
                conn = await self.pool.connect(
                    upstream.host, 
                    upstream.port, 
                    Scheme.udp, 
                    proxy
                )
            except ConnectionError as exc:
                logger.warning(exc)
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

    async def _resolve_by_https(self, query, upstream):
        try:
            with await self.pool.connect(
                upstream.host, 
                upstream.port, 
                Scheme.tls, 
                self._get_proxy(upstream)
            ) as conn:
                q = base64.b64encode(query).decode().rstrip('=')
                return (await https.Client(upstream.hostname, conn).get(
                    upstream.path,
                    {'dns': q}, 
                    [("Content-type", "application/dns-message")]
                )).body
        except HttpException as exc:
            logger.warning('HTTP exception: %s', exc)
        except ConnectionError as exc:
            logger.warning(exc)

    async def _resolve_by_tls(self, query, upstream):
        try:
            with await self.pool.connect(
                upstream.host, 
                upstream.port, 
                Scheme.tls, 
                self._get_proxy(upstream)
            ) as conn:
                query_size = struct.pack('!H', len(query))
                conn.writer.write(query_size + query)
                await conn.writer.drain()
                response_head = await conn.reader.readexactly(2)
                response_size = struct.unpack('!H', response_head)[0]
                return await conn.reader.readexactly(response_size)
        except asyncio.exceptions.IncompleteReadError:
            logger.error('Failed to read data from %s:%d', upstream.host, upstream.port)
        except ConnectionError as exc:
            logger.warning(exc)

    async def fetch(self, url, **kwargs):
        return await https.fetch(url, self.handle, 
                                      self.pool, 
                                      self.proxy,
                                      **kwargs)

    def _get_timeout(self, upstream):
        return self.timeout if upstream.timeout is None else upstream.timeout

    async def handle(self, request, **kwargs):
        logger.debug('DNS query:\n%s', request)
        data = DNSRecord.pack(request)
        for upstream in (self.upstreams.sorted() if 'upstreams' not in kwargs else kwargs['upstreams']):
            if upstream.disable: continue
            if isinstance(upstream, DnsUpstream):
                resolver = self._resolve_by_dns
            elif isinstance(upstream, HttpsUpstream):
                resolver = self._resolve_by_https
            elif isinstance(upstream, TlsUpstream):
                resolver = self._resolve_by_tls
            else:
                raise NotImplementedError('Unspported upstream')

            try:
                with self.stats.record(upstream):
                    response_data = await asyncio.wait_for(
                        asyncio.shield(resolver(data, upstream)), 
                        self._get_timeout(upstream)
                    )
                    if response_data is None:
                        raise EmptyValueError('Empty response data received')
                    try:
                        response = DNSRecord.parse(response_data)
                    except DNSError:
                        raise UnexpectedValueError('Invalid response data received')
                    if request.header.id != response.header.id:
                        raise UnexpectedValueError('Response id does not match')
                    logger.debug('DNS response:\n%s', response)
                    return response
            except ValueError:
                logger.warning('Failed to resolve by %s:%d' % upstream.to_addr())
            except TimeoutError:
                logger.info('Upstream server %s:%d response timeout' % upstream.to_addr())

    async def _handle(self, request):
        resolver = self.middlewares if self.middlewares else self
        if request.header.q > 1:
            coroutines = []
            for q in request.questions:
                _req = request.truncate()
                _req.add_question(q)
                coroutines.append(resolver.handle(_req))
            response = DNSRecord(DNSHeader(id=request.header.id,
                                           bitmap=request.header.bitmap,
                                           qr=1, ra=1, aa=1),
                                questions=request.questions)
            for _resp in await asyncio.gather(*coroutines):
                if _resp and _resp.header.a > 0:
                    response.add_answer(_resp.a)
            return response
        return await resolver.handle(request)

    def on_response(self, request, addr, future):
        response = future.result()
        if response is None:
            logger.info('Failed to resolve domain name "%s", upstream servers are unreachable', request.q.qname)
            return

        logger.debug('Send response to %s:%d\n%s' % (addr + (response, )))
        self.transport.sendto(DNSRecord.pack(response), addr)

    def on_request(self, data, addr):
        request = DNSRecord.parse(data)
        logger.debug('Received request from %s:%d\n%s' % (addr + (request, )))
        task = self.loop.create_task(self._handle(request))
        task.add_done_callback(functools.partial(self.on_response, request, addr))

    def abort(self):
        self.status = self.Status.stop_pedding
        logger.info('DNS serivce aborted')
        return self.abort_event.set()

    async def reload(self):
        # TODO: 
        pass

    async def restart(self):
        self.status = self.Status.restart_pedding
        logger.info('Restarting service')
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: ServerProtocol(self),
            local_addr=(self.host, self.port)
        )
        self.status = self.Status.running
        logger.info('DNS service restarted')

    def on_error_restart(self):
        if self.status != self.Status.running:
            return
        return self.loop.create_task(self.restart())

    async def run(self):
        self.status = self.Status.start_pedding
        if not await self.middlewares.bootstrap():
            logger.error('Failed to bootstrap')
            return
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: ServerProtocol(self),
                local_addr=(self.host, self.port)
            )
        except OSError as exc:
            logger.error('Failed to start DNS service: %s', exc)
            return

        self.status = self.Status.running
        logger.info('DNS serivce started')

        try:
            await self.abort_event.wait()
        except asyncio.CancelledError:
            logger.debug('DNS serivce interrupted')
        finally:
            self.transport.close()
            self.status = self.Status.stopped
            logger.info('DNS serivce stopped')

    def open_geoip(self):
        return maxminddb.open_database(self.config['geoip'])
