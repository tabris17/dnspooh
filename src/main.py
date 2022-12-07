import argparse
import asyncio
import logging
import sys

import https
import server

from config import *
from upstream import *


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog = 'DNSPooh',
        description = 'A MitM DNS Proxy',
        add_help=False
    )

    parser.add_argument('-c', '--config', metavar='file', dest='config',
                        help='config file path (example "config.yml")')
    parser.add_argument('-u', '--upstream', metavar='servers', dest='upstreams', nargs='+',
                        help='space-separated upstream DNS servers list')
    parser.add_argument('-t', '--timeout', metavar='ms', dest='timeout', type=int, 
                        help='milliseconds for upstream DNS response timeout (default %d ms)' % (UPSTREAM_TIMEOUT, ))
    parser.add_argument('-h', '--host', metavar='host', dest='host', 
                        help='local DNS proxy server listening host (default "%s")' % (LISTEN_HOST, ))
    parser.add_argument('-p', '--port', metavar='port', dest='port', type=int, 
                        help='local DNS proxy server listening port (default "%s")' % (DEFAULT_DNS_PORT, ))
    parser.add_argument('-D', '--debug', action='store_true', help='display debug message')
    parser.add_argument('-d', '--dump', action='store_true', default=False, help='dump pretty config data')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('--help', action='help', help='show this help message and exit')

    return parser.parse_args(sys.argv[1:])


async def main():
    args = parse_arguments()
    config = Config.load(args)
    if args.dump:
        from pprint import pprint
        pprint(config.conf)
        return

    debug = config['debug']
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(name)s.%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    logger = logging.getLogger(main.__name__)

    loop = asyncio.get_running_loop()
    loop.set_debug(debug)

    dns_server = server.Server(config, loop)
    http_server = https.Server(config, loop)
    try:
        await asyncio.gather(dns_server.run(), http_server.run())
    except asyncio.CancelledError:
        logger.info('exit.')


if __name__ == '__main__':
    asyncio.run(main())
