import logging

import dnslib
import netaddr

from . import Middleware
from exceptions import InvalidConfig


logger = logging.getLogger(__name__)


class Rule: pass


class GeoipRule(Rule):
    pass


class DomainRule(Rule):
    pass


class DomainSuffixRule(Rule):
    pass


class DomainKeywordRule(Rule):
    pass


class DomainRegexRule(Rule):
    pass


class IpRangeRule(Rule):
    pass


def parse_rule(*args):
    name = args[0].upper()
    if name == 'DOMAIN':
        return 
    elif name == 'DOMAIN-SUFFIX':
        pass
    elif name == 'DOMAIN-KEYWORD':
        pass
    elif name == 'DOMAIN-REGEX':
        pass
    elif name == 'GEOIP':
        pass
    elif name == 'IP-CIDR':
        pass
    else:
        raise InvalidConfig('Invalid rule name %s' % (name, ))


class Action: pass


class BlockAction(Action):
    pass


def parse_action(*args):
    pass


class RulesMiddleware(Middleware):
    def __init__(self, next, *rules):
        super().__init__(next)
        self.rules = rules

    def _process_request(self, request):
        return request

    def _process_response(self, response):
        with self.server.open_geoip() as geoip:
            for answer in response.rr:
                if answer.rtype == dnslib.QTYPE.A:
                    logger.info(geoip.get('146.19.22.103'))
        return response

    async def handle(self, request, **kwargs):
        request = self._process_request(request)
        response = await super().handle(request, **kwargs)
        return self._process_response(response)
