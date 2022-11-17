import asyncio
import ssl


class PoolStreamReaderProtocol(asyncio.streams.StreamReaderProtocol):
    def eof_received(self):
        super().eof_received()
        return False

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if self._connection_lost_cb is not None:
            self._connection_lost_cb(self.name)

    def __init__(self, name, stream_reader, on_connection_lost):
        super.__init__(stream_reader)
        self.name = name
        self._connection_lost_cb = on_connection_lost


class Pool:
    DEFAULT_LIMIT = 2 ** 16

    def __init__(self, loop=None):
        self._connections = dict()
        self._loop = asyncio.get_running_loop() if loop is None else loop

    def _generate_name(self, scheme, host, port):
        return '{scheme}:{host}:{port}'.format(scheme=scheme, host=host, port=port)

    def get_connection(self, scheme, host, port):
        connection_name = self._generate_name(scheme, host, port)
        if connection_name in self._connections:
            transport = self._connections[connection_name]
            if not transport.is_closing():
                return transport
            del self._connections[connection_name]

        self.open_connection(host, port)

    async def open_connection(self, host, port, *,
                              limit=DEFAULT_LIMIT, **kwds):
        ssl_context = ssl.create_default_context()
        reader = asyncio.StreamReader(limit=limit, loop=self._loop)
        protocol = PoolStreamReaderProtocol(reader, loop=self._loop)
        transport, _ = await self._loop.create_connection(
            lambda: protocol, host, port, **kwds)
        ssl_transport = await self._loop.start_tls(transport, protocol, ssl_context)
        writer = asyncio.StreamWriter(ssl_transport, protocol, reader, self._loop)
        return reader, writer



