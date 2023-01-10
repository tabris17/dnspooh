import asyncio
import logging
import https
import dnslib
from pool import Pool, Scheme
from proxy import parse_proxy


def dns_query():
    request = dnslib.DNSRecord.question('baidu.com')
    request.add_question(dnslib.DNSQuestion('qq.com'))
    logging.info(request)
    response = dnslib.DNSRecord.parse(request.send('127.0.0.1'))
    logging.info(response)

async def proxy():
    pool = Pool()
    proxy = parse_proxy('socks5://127.0.0.1:7890')
    conn = await pool.connect('112.80.248.75', 443, Scheme.tls, proxy)
    https_client = https.Client('www.baidu.com', conn)
    response = await https_client.get('/')
    #print(response)
    response = await https_client.get('/')

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

async def form_data():
    pool = Pool()
    conn = await pool.connect('localhost', 8008, Scheme.tcp)
    https_client = https.Client('localhost:8008', conn)
    form_data = https.FormData()
    form_data.append('name123', 'value123213')
    response = await https_client.post('/index.php?asd=123', body=form_data)

async def fetch_url():
    async def resolver(request):
        return dnslib.DNSRecord.parse(b'\xfd\xa8\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03raw\x0bhellogithub\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00&\x00\x04\xa5\x9a\x05\x1b')
    response = await https.fetch('https://raw.hellogithub.com/hosts', resolver, Pool())
    print(response)

def parsing():
    from middlewares.rules import RuleIfParser
    import ipaddress

    parser = RuleIfParser()

    result = parser.parse('not not .com in domain or domain starts with 123.com or domain is not xyz.com')
    print(result.test(domain='xyz.com'), '<-', result)
    result = parser.parse('(ip is ff00:123:123:123:123:123:123:123) and (ip in 127.0.0.1/8) and (ip is ff00::123:123) and (ip is ff00::123:192.168.0.1)')
    print(result.test(ip=ipaddress.ip_address('129.168.253.1'), geoip='cn'), '<-', result)
    result = parser.parse('ip is 127.0.0.1 and ip is 192.168.1.1')
    print(result.test(ip=ipaddress.ip_address('129.168.253.1'), geoip='cn'), '<-', result)
    result = parser.parse('ip is 127.0.0.1 and ip is 192.168.1.1')
    print(result.test(ip=ipaddress.ip_address('129.168.253.1'), geoip='cn'), '<-', result)
    result = parser.parse('domain match /asdsad\d+/')
    print(result.test(domain='asdsad123'), '<-', result)

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    parsing()
    #asyncio.run(fetch_url())
