import asyncio
import ssl
import logging

import certifi

from .helpers import Scheme


logger = logging.getLogger(__name__)


class PoolStreamReaderProtocol(asyncio.StreamReaderProtocol):
    def eof_received(self):
        super().eof_received()
        return False

    def data_received(self, data):
        return super().data_received(data)

    def connection_made(self, transport):
        return super().connection_made(transport)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if self._connection_lost_cb and self.conn:
            self.conn.exc = exc
            self._connection_lost_cb(self.conn)

    def __init__(self, stream_reader, on_connection_lost=None, **kwds):
        self._connection_lost_cb = on_connection_lost
        self.conn = None
        super().__init__(stream_reader, **kwds)


class Connection:
    def __init__(self, name, reader, writer, udp_tunnel=None):
        self.name = name
        self.reader = reader
        self.writer = writer
        self.udp_tunnel = udp_tunnel
        self.exc = None
        self.idle = True
        self._is_wild = True

    def is_wild(self):
        return self._is_wild

    def register(self):
        self._is_wild = False
        self.writer.transport.get_protocol().conn = self

    def __enter__(self):
        self.idle = False
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None or self.is_wild():
            self.writer.transport.close()
        self.idle = True

    def __repr__(self):
        return self.name

    def is_closing(self):
        return self.writer.transport.is_closing()

    def udp_tunnel_enabled(self):
        return self.udp_tunnel is not None

    def close(self):
        return self.writer.transport.close()

    def abort(self):
        return self.writer.transport.abort()


class Pool:
    DEFAULT_LIMIT = 2 ** 16
    DEFAULT_SIZE = 2 ** 10

    def __init__(self, loop=None, size=DEFAULT_SIZE):
        self.size = size
        self.total = 0
        self.connections = dict()
        self.loop = asyncio.get_running_loop() if loop is None else loop

    def add(self, conn):
        if self.DEFAULT_SIZE <= self.total:
            return False

        if conn.is_closing():
            raise ConnectionError('Fail to connect "%s"' % (conn.name, ))

        if conn.name in self.connections:
            if conn in self.connections[conn.name]:
                return False
            self.connections[conn.name].add(conn)
        else:
            self.connections[conn.name] = set([conn])
        self.total += 1
        conn.register()
        logger.debug('Add "%s" to connection pool', conn.name)
        return True

    def remove(self, conn):
        if conn.name in self.connections:
            if conn in self.connections[conn.name]:
                self.connections[conn.name].remove(conn)
                self.total -= 1
                return True

        return False

    def get(self, conn_name):
        if conn_name not in self.connections:
            return
        for conn in self.connections[conn_name]:
            if conn.idle:
                return conn
        return

    def on_connection_lost(self, conn):
        self.remove(conn)
        logger.debug('Remove "%s" from connection pool', conn.name)

    async def connect(self, host, port, 
                      scheme=Scheme.tcp, proxy=None, 
                      limit=DEFAULT_LIMIT, pooled=True, **kwds):
        conn_name = _make_conn_name(host, port, scheme, proxy)
        conn = self.get(conn_name)
        if conn:
            return conn

        reader = asyncio.StreamReader(limit=limit, loop=self.loop)
        protocol = PoolStreamReaderProtocol(reader, self.on_connection_lost, loop=self.loop)
        if proxy:
            try:
                transport, _ = await self.loop.create_connection(
                    lambda: protocol, proxy.host, proxy.port, **kwds)
            except OSError as exc:
                raise ConnectionError('Cannot connect to proxy "%s:%d": %s' % (proxy.host, proxy.port, exc))
            writer = asyncio.StreamWriter(transport, protocol, reader, self.loop)
            if scheme == Scheme.udp:
                conn = Connection(
                    conn_name, reader, writer, 
                    await proxy.make_udp_tunnel(reader, writer, (host, port))
                )
                if pooled: self.add(conn)
                return conn
            if not await proxy.handshake(reader, writer, (host, port)):
                raise ConnectionError('Failed to handshake with proxy "%s"' % (proxy.url, ))
        elif scheme == Scheme.udp:
            raise ConnectionError('Naked UDP protocol does not supported')
        else:
            try:
                transport, _ = await self.loop.create_connection(
                    lambda: protocol, host, port, **kwds)
            except OSError as exc:
                raise ConnectionError('Cannot connect to server "%s:%d": %s' % (host, port, exc))
            writer = asyncio.StreamWriter(transport, protocol, reader, self.loop)

        if scheme == Scheme.tls:
            try:
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                transport = await self.loop.start_tls(transport, protocol, ssl_context)
                writer = asyncio.StreamWriter(transport, protocol, reader, self.loop)
            except ssl.SSLError as exc:
                raise ConnectionError('Failed to establish tls connection: %s' % (exc, ))

        conn = Connection(conn_name, reader, writer)
        if pooled: self.add(conn)
        return conn
        
    def dispose(self):
        for conn_set in self.connections.values():
            for conn in conn_set:
                conn.abort()


def _make_conn_name(host, port, scheme, proxy):
    name = '%s://%s:%d' % (scheme.name, host, port)
    return name if proxy is None else '%s/%s' % (proxy.url, name)
