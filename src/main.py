import argparse
import asyncio
import logging
import sys

from config import *
from server import Server
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
                        help='milliseconds for upstream DNS response timeout (default "{0}"ms)'.format(UPSTREAM_TIMEOUT))
    parser.add_argument('-h', '--host', metavar='host', dest='host', 
                        help='local DNS proxy server listening host (default "{0}")'.format(LISTEN_HOST))
    parser.add_argument('-p', '--port', metavar='port', dest='port', type=int, 
                        help='local DNS proxy server listening port (default "{0}")'.format(DEFAULT_DNS_PORT))
    parser.add_argument('-D', '--debug', action='store_true', help='display debug message')
    parser.add_argument('-d', '--dump', action='store_true', default=False, help='dump pretty config data')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('--help', action='help', help='show this help message and exit')

    return parser.parse_args(sys.argv[1:])


def init_logging(level):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )


async def main():
    args = parse_arguments()
    config = Config.load(args)
    if args.dump:
        from pprint import pprint
        pprint(config.conf)
        return

    debug = config['debug']
    init_logging(level=logging.DEBUG if debug else logging.INFO)
    main_loop = asyncio.get_running_loop()
    main_loop.set_debug(debug)

    server = Server(config)
    await server.run()


if __name__ == '__main__':
    asyncio.run(main())
