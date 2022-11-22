import asyncio
import base64
import logging
import socket
import ssl
import struct

from dnslib import DNSRecord

import https
from config import DnsUpstream, HttpsUpstream, TlsUpstream
from middleware import *
from pool import Pool


class ServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy):
        super().__init__()
        self.loop = asyncio.get_running_loop()
        self.proxy = proxy

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        logging.debug('Received request from {0}'.format(addr))
        self.loop.create_task(self.proxy.on_request(data, addr))


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
        logging.debug('Proxy serivce initialized')

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
                    raise RuntimeError('Duplicated upstream name "{0}"'.format(upstream.name))
                named_upstreams[upstream.name] = upstream

            if upstream.group:
                if upstream.group in grouped_upstreams:
                    grouped_upstreams[upstream.group].append(upstream)
                else:
                    grouped_upstreams[upstream.group] = [upstream]

        for hostname_upstream in hostname_upstreams:
            request = DNSRecord.question(hostname_upstream.hostname)
            response = await self.handle(request, bootstrap_upstreams)
            if not response or response.header.a == 0:
                raise RuntimeError('Failed to bootstrap: cannot resolve "{0}"'.format(hostname_upstream.hostname))
            hostname_upstream.host = str(response.rr[0].rdata)

        logging.debug('Proxy serivce bootstrapped')

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
        q = base64.b64encode(query).decode().rstrip('=')
        http_response = await https.get(
            upstream.host, 
            upstream.port, 
            upstream.hostname, 
            upstream.path + '?dns=' + q, 
            [("Content-type", "application/dns-message")]
        )
        response = http_response.body
        return response

    async def resolve_by_tls(self, query, upstream):
        reader, writer = await asyncio.open_connection(
            upstream.host, 
            upstream.port, 
            ssl=ssl.create_default_context(),
            server_hostname=upstream.hostname
        )
        try:
            query_size = struct.pack('H', socket.htons(len(query)))
            writer.write(query_size + query)
            await writer.drain()
            response_head = await reader.readexactly(2)
            response_size = socket.ntohs(struct.unpack('=H', response_head)[0])
            response = await reader.readexactly(response_size)
        finally:
            writer.transport.close()
        return response

    async def handle(self, request, upstreams=None):
        response = None
        data = DNSRecord.pack(request)
        for upstream in (self.upstreams if upstreams is None else upstreams):
            if isinstance(upstream, DnsUpstream):
                resolver = self.resolve_by_dns
            elif isinstance(upstream, HttpsUpstream):
                resolver = self.resolve_by_https
            elif isinstance(upstream, TlsUpstream):
                resolver = self.resolve_by_tls
            else:
                raise NotImplementedError('Unspported upstream')
            try:
                response = await asyncio.wait_for(resolver(data, upstream), self.timeout)
                if response is not None:
                    break
            except TimeoutError:
                logging.info('Upstream server {0} response timeout'.format(upstream.to_addr()))

        return DNSRecord.parse(response) \
            if response is not None else None

    async def on_request(self, data, addr):
        request = DNSRecord.parse(data)
        response = await (self.middleware if self.middleware else self).handle(request)
        if response is None:
            logging.info('Failed to resolve domain name "{0}", upstream servers are unreachable'.format(request.q.qname))
            return

        logging.debug('Send response to {0}'.format(addr))
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

        logging.info('Proxy serivce started')

        try:
            await self.abort_event.wait()
        except asyncio.CancelledError:
            logging.debug('Proxy serivce interrupted')
        finally:
            self.transport.close()
            logging.info('Proxy serivce stopped')
