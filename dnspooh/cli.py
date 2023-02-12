import argparse
import asyncio
import logging
import sys

from . import https
from . import server
from . import __version__, __description__
from .config import *
from .upstream import *


logger = logging.getLogger(__name__)


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog = __package__,
        description = __description__,
        add_help=False
    )

    parser.add_argument('-c', '--config', metavar='file', dest='config',
                        help='config file path (example "%s")' % (CONFIG_FILE, ))
    parser.add_argument('-u', '--upstream', metavar='dns_server', dest='upstreams', nargs='+',
                        help='space-separated upstream DNS servers list')
    parser.add_argument('-t', '--timeout', metavar='ms', dest='timeout', type=int, 
                        help='milliseconds for upstream DNS response timeout (default %d ms)' % (UPSTREAM_TIMEOUT, ))
    parser.add_argument('-l', '--listen', metavar='addr', dest='listen', nargs='+', 
                        help='binding to local address and port for DNS proxy server (default "%s")' % (LISTEN_ADDRESS, ))
    parser.add_argument('-o', '--output', metavar='file', dest='output', 
                        help='write stdout to the specified file')
    parser.add_argument('-S', '--secure-only', dest='secure', action='store_true', help='use DoT/DoH upstream servers only')
    parser.add_argument('-6', '--enable-ipv6', dest='ipv6', action='store_true', help='enable IPv6 upstream servers')
    parser.add_argument('-D', '--debug', action='store_true', help='display debug message')
    parser.add_argument('-d', '--dump', action='store_true', help='dump pretty config data')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-h', '--help', action='help', help='show this help message and exit')

    return parser.parse_args(sys.argv[1:])


async def startup():
    try:
        debug = True
        args = parse_arguments()
        config = Config.load(args)
        if args.dump:
            from pprint import pprint
            pprint(config.conf)
            return
            
        output_file = config.get('output')
        if output_file:
            logging.root.addHandler(logging.FileHandler(output_file))

        debug = config['debug']
        if debug:
            logging.root.setLevel(logging.DEBUG)

        loop = asyncio.get_running_loop()
        loop.set_debug(debug)
        loop.set_exception_handler(lambda _, context: logger.warning(context['message']))

        dns_server = server.Server(config, loop)
        dispatcher = https.Dispatcher(dns_server)
        http_server = https.Server(config, dispatcher, loop)

        await asyncio.gather(dns_server.run(), http_server.run())
    except asyncio.CancelledError:
        logger.info('Exit')
    except InvalidConfig as exc:
        logger.error('Invalid config: %s', exc)
    except Exception as exc:
        if debug:
            raise
        else:
            logger.error('Unexpected error: %s', exc)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s.%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()]
    )
    try:
        asyncio.run(startup())
    except KeyboardInterrupt:
        pass
