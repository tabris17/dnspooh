import unittest
import pathlib
import tempfile

import dnslib

from dnspooh.middlewares import BlockMiddleware
from . import Server, dns_request, dns_answer, dns_response


server = Server()


async def create_middleware(**kwargs):
    with tempfile.TemporaryDirectory() as path:
        base_path = pathlib.Path(path)
        filenames = []
        for name, content in kwargs.items():
            block_filename = str(base_path.joinpath(name + '.txt'))
            filenames.append(block_filename)
            with open(block_filename, 'w+') as fp:
                fp.write(content)
        block = BlockMiddleware(*filenames)
        block.initialize(server, 'block')
        await block.bootstrap()
    return block


class BlockTest(unittest.IsolatedAsyncioTestCase):
    async def test_block(self):
        block = await create_middleware(
            block1='www.baidu.com', 
            block2='weixin.qq.com',
            block3='ip:127.0.0.1', 
            block4='ip:127.0.0.2'
        )
        request = dns_request('www.baidu.com')
        response = await block.handle(request, answer='127.0.0.1')
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        request = dns_request('weixin.qq.com')
        response = await block.handle(request, answer='127.0.0.1')
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

        request = dns_request('localhost')
        response = await block.handle(request, answer='127.0.0.1')
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        request = dns_request('localhost')
        response = await block.handle(request, answer='127.0.0.2')
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
