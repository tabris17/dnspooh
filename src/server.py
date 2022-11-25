import asyncio
import base64
import logging
import struct

from dnslib import DNSRecord

import https
from config import DnsUpstream, HttpsUpstream, TlsUpstream
from middleware import *
from pool import Pool
from scheme import Scheme


class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        super().__init__()
        self.loop = asyncio.get_running_loop()
        self.server = server

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.loop.create_task(self.server.on_request(data, addr))


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


class Server:
    def __init__(self, config):
        self.config = config
        self.pool = Pool()
        self.loop = asyncio.get_running_loop()
        self.abort_event = asyncio.Event()
        self.middleware = None # CacheMiddleware(RuleMiddleware(self), 4096, 5000)
        self.transport = None
        logging.debug('Serivce initialized')

    async def bootstrap(self, host, port, timeout, upstreams, proxy):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.upstreams = upstreams
        self.proxy = proxy
        bootstrap_upstreams = []
        hostname_upstreams = []
        grouped_upstreams = dict()
        named_upstreams = dict()

        for upstream in upstreams:
            if upstream.host:
                bootstrap_upstreams.append(upstream)
            else:
                hostname_upstreams.append(upstream)

            if upstream.name:
                if upstream.name in named_upstreams:
                    raise RuntimeError('Duplicated upstream name "%s"' % (upstream.name, ))
                named_upstreams[upstream.name] = upstream

            if upstream.group:
                if upstream.group in grouped_upstreams:
                    grouped_upstreams[upstream.group].append(upstream)
                else:
                    grouped_upstreams[upstream.group] = [upstream]

        for hostname_upstream in hostname_upstreams:
            request = DNSRecord.question(hostname_upstream.hostname)
            response = await self.handle(request, upstreams=bootstrap_upstreams)
            if not response or response.header.a == 0:
                raise RuntimeError('Failed to bootstrap: cannot resolve "%s"' % (hostname_upstream.hostname, ))
            hostname_upstream.host = str(response.rr[0].rdata)

        logging.debug('Serivce bootstrapped')

    async def resolve_by_dns(self, query, upstream):
        response_future = self.loop.create_future()
        upstream_addr = upstream.to_addr()
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: QueryProtocol(query, response_future),
            remote_addr=upstream_addr
        )
        try:
            response = await response_future
        finally:
            transport.close()
        return response

    async def resolve_by_https(self, query, upstream):
        conn = await self.pool.connect(
            upstream.host, 
            upstream.port, 
            Scheme.tls, 
            self.proxy if upstream.proxy is None else upstream.proxy
        )
        with conn:
            q = base64.b64encode(query).decode().rstrip('=')
            return (await https.Client(conn).get(
                upstream.path + '?dns=' + q, 
                upstream.hostname, 
                [("Content-type", "application/dns-message")]
            )).body

    async def resolve_by_tls(self, query, upstream):
        conn = await self.pool.connect(
            upstream.host, 
            upstream.port, 
            Scheme.tls, 
            self.proxy if upstream.proxy is None else upstream.proxy
        )
        with conn:
            query_size = struct.pack('!H', len(query))
            conn.writer.write(query_size + query)
            await conn.writer.drain()
            response_head = await conn.reader.readexactly(2)
            response_size = struct.unpack('!H', response_head)[0]
            return await conn.reader.readexactly(response_size)

    async def handle(self, request, **kwargs):
        response = None
        data = DNSRecord.pack(request)
        for upstream in (self.upstreams if 'upstreams' not in kwargs else kwargs['upstreams']):
            if isinstance(upstream, DnsUpstream):
                resolver = self.resolve_by_dns
            elif isinstance(upstream, HttpsUpstream):
                resolver = self.resolve_by_https
            elif isinstance(upstream, TlsUpstream):
                resolver = self.resolve_by_tls
            else:
                raise NotImplementedError('Unspported upstream')
            try:
                response = await asyncio.wait_for(
                    asyncio.shield(resolver(data, upstream)), 
                    self.timeout if upstream.timeout is None else upstream.timeout
                )
                if response is not None:
                    break
            except TimeoutError:
                logging.info('Upstream server %s:%d response timeout' % upstream.to_addr())

        return DNSRecord.parse(response) if response is not None else None

    async def on_request(self, data, addr):
        request = DNSRecord.parse(data)
        logging.debug('Received request from %s:%d; qname=%s; qtype=%s' % (addr + (request.q.qname, request.q.qtype)))
        response = await (self.middleware if self.middleware else self).handle(request)
        if response is None:
            logging.info('Failed to resolve domain name "%s", upstream servers are unreachable' % (request.q.qname, ))
            return

        logging.debug('Send response to %s:%d' % addr)
        self.transport.sendto(DNSRecord.pack(response), addr)

    def abort(self):
        return self.abort_event.set()

    async def run(self):
        host = self.config['host']
        port = self.config['port']
        timeout = self.config['timeout']
        upstreams = self.config['upstreams']
        proxy = self.config['proxy']
        await self.bootstrap(host, port, timeout, upstreams, proxy)

        try:
            loop = asyncio.get_running_loop()
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: ServerProtocol(self),
                local_addr=(self.host, self.port)
            )
        except OSError as e:
            logging.error(e)
            return

        logging.info('Serivce started')

        try:
            await self.abort_event.wait()
        except asyncio.CancelledError:
            logging.debug('Serivce interrupted')
        finally:
            self.transport.close()
            logging.info('Serivce stopped')
