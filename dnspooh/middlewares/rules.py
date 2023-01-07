import logging
#import 

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
        pass
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


class RulesMiddleware(Middleware):
    def __init__(self, next, *rules):
        super().__init__(next)
        self.rules = rules


    async def handle(self, request, **kwargs):
        return await super().handle(request, **kwargs)
        
