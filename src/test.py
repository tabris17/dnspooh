import asyncio
import logging
import https
from pool import Pool, Scheme
from proxy import parse_proxy


async def proxy():
    pool = Pool()
    proxy = parse_proxy('socks5://127.0.0.1:7890')
    conn = await pool.connect('112.80.248.75', 443, Scheme.tls, proxy)
    https_client = https.Client(conn)
    response = await https_client.get('/', 'www.baidu.com')
    #print(response)
    response = await https_client.get('/', 'www.baidu.com')

async def datagram():
    class DatagramProtocol(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            transport.sendto(data, addr)
            logging.info('data: %s; from: %s:%d', data, *addr)

        def error_received(self, exc):
            logging.info('Server error: %s', exc)

    local_addr = ('127.0.0.1', 1234)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DatagramProtocol(),
        local_addr=local_addr
    )
    await asyncio.sleep(10)
    transport.close()
    transport.abort()
    await asyncio.sleep(0.0001)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DatagramProtocol(),
        local_addr=local_addr
    )

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    asyncio.run(proxy())
