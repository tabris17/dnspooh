import dnslib
import logging
import inspect

from dnspooh.server import Server as ServerBase


logger = logging.getLogger(__name__)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s.%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

def dns_request(domain):
    return dnslib.DNSRecord.question(domain)


def dns_answer(request, ip_addr):
    request.add_answer(dnslib.RR(request.q.qname, dnslib.QTYPE.A,
        rdata=dnslib.A(ip_addr)))
    return request


def dns_response(domain, *ip_addrs):
    request = dns_request(domain)
    for ip_addr in ip_addrs:
        dns_answer(request, ip_addr)
    return request


class LoggerMixin:
    def log_call(self):
        func = inspect.stack()[1].function
        cls = self.__class__.__name__
        logger.info('%s.%s() is called', cls, func)


class Server(ServerBase, LoggerMixin):
    def __init__(self):
        pass

    def create_scheduled_task(self, coro, timer, name=None):
        self.log_call()

    async def bootstrap(self):
        self.log_call()
        return True

    async def handle(self, request, **kwargs):
        dns_answer(request, kwargs['answer'])
        return request


from .rules import RuleIfTest, RuleThenTest, RuleBeforeTest, RuleAfterTest
from .block import BlockTest

__all__ = (RuleIfTest, RuleThenTest, RuleBeforeTest, RuleAfterTest, BlockTest)
