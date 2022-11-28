import asyncio
import logging
import https
from pool import Pool, Scheme
from proxy import parse_proxy


async def main():
    pool = Pool()
    proxy = parse_proxy('socks5://127.0.0.1:7890')
    conn = await pool.connect('112.80.248.75', 443, Scheme.tls, proxy)
    https_client = https.Client(conn)
    response = await https_client.get('/', 'www.baidu.com')
    #print(response)
    response = await https_client.get('/', 'www.baidu.com')

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    asyncio.run(main())
