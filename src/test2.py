import asyncio
 
 
async def main():
    class DatagramProtocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport
            return super().connection_made(transport)

        def datagram_received(self, data, addr):
            print('Received %r from %s' % (data.decode(), addr))
            asyncio.get_running_loop().\
                call_later(2, lambda: self.transport.sendto(data, addr))
 
        def error_received(self, exc):
            print('Received error:', exc)
            self.transport.close()
        
        def connection_lost(self, exc):
            super().connection_lost(exc)
            print('Restarting server')
            task = asyncio.create_task(restart())
            return
 
    async def restart():
        nonlocal transport
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DatagramProtocol(),
            local_addr=local_addr
        )

    local_addr = ('127.0.0.1', 9999)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DatagramProtocol(),
        local_addr=local_addr
    )
    try:
        await asyncio.sleep(3600)
    finally:
        transport.close()
 
 
asyncio.run(main())