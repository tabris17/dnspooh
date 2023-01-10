import logging
import re

import dnslib
import netaddr

from . import Middleware
from exceptions import InvalidConfig


logger = logging.getLogger(__name__)


class RequestMatch:
    def __init__(self, condition):
        self.condition = condition

    def match(self, request):
        domain = request.q.qname.idna().rstrip('.')
        return self.match_domain(domain)

    def match_domain(self, domain):
        raise NotImplemented()


class DomainEqualMatch(RequestMatch):
    def match_domain(self, domain):
        return self.condition == domain


class DomainSuffixMatch(RequestMatch):
    def match_domain(self, domain):
        return domain.endswith(self.condition)


class DomainKeywordMatch(RequestMatch):
    def match_domain(self, domain):
        return self.condition in domain


class DomainRegexMatch(RequestMatch):
    def __init__(self, regex, flag=re.RegexFlag.NOFLAG):
        self.regex = regex
        self.flag = flag

    def match_domain(self, domain):
        return re.fullmatch(self.regex, domain, self.flag) is not None


class ResponseMatch:
    def __init__(self, condition):
        self.condition = condition

    def match(self, response):
        matched_idx = []
        for idx, record in enumerate(response.rr):
            if self.match_record(record):
                matched_idx.append(idx)
        return matched_idx

    def match_record(self, record):
        if record.rtype in (dnslib.QTYPE.AAAA, dnslib.QTYPE.A):
            return self.match_ip(str(record.rdata))
        return False

    def match_ip(self, ip_addr):
        raise NotImplemented()


class IpRangeMatch(ResponseMatch):
    def __init__(self, ip_cidr):
        self.ip_cidr = netaddr.IPNetwork(ip_cidr)

    def match_ip(self, ip_addr):
        return ip_addr in self.ip_cidr


class GeoipMatch(ResponseMatch):
    def __init__(self, country_code, server):
        self.country_code = country_code
        self.server = server

    def match_ip(self, ip_addr):
        with self.server.open_geoip() as geoip:
            result = geoip.get(ip_addr)
        if result is None:
            return False
        return result['country']['iso_code'] == self.code


class Rule:
    pass


class RulesMiddleware(Middleware):
    '''
    阻止域名解析
    自定义域名解析结果
    重定向到其他域名
    过滤返回的RR
    指定upstream
    '''
    def __init__(self, next, *rules):
        super().__init__(next)
        self.rules = [self._parse_rule(rule) for rule in rules]

    def _parse_rule(self, rule):
        request_match = self._parse_request_match(rule[0])
        response_match = self._parse_response_match(rule[1])

    def _parse_request_match(self, condition):
        if isinstance(condition, dict):
            key = next(iter(condition))
            value = condition[key]
            if key == 'keyword':
                return DomainKeywordMatch(value)
            elif key == 'regex':
                return DomainRegexMatch(value)
            elif key == 'suffix':
                return DomainSuffixMatch(value)
            elif key == 'equal':
                return DomainEqualMatch(value)
        elif isinstance(condition, str):
            if condition.startswith('.'):
                return DomainSuffixMatch(condition)
            elif condition == '-':
                return
            else:
                return DomainEqualMatch(condition)
        raise InvalidConfig('Invalid request match condition: %s' % (condition, ))

    def _parse_response_match(self, condition):
        if isinstance(condition, dict):
            key = next(iter(condition))
            value = condition[key]
            if key == 'geoip':
                return GeoipMatch(value, self.server)
        elif isinstance(condition, str):
            if condition == '-':
                return
            else:
                return IpRangeMatch(condition)
        raise InvalidConfig('Invalid response match condition: %s' % (condition, ))

    async def handle(self, request, **kwargs):
        response = await super().handle(request, **kwargs)
        return response
