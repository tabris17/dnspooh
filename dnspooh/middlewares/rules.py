import logging
import re
import enum
import ipaddress
import itertools

import dnslib
import netaddr
import pyparsing

from . import Middleware
from exceptions import InvalidConfig


logger = logging.getLogger(__name__)


class RuleIfParser:
    class OpCode(enum.Enum):
        DOMAIN_CONTAINS = enum.auto()
        DOMAIN_NOT_CONTAINS = enum.auto()
        DOMAIN_EQ = enum.auto()
        DOMAIN_NOT_EQ = enum.auto()
        DOMAIN_STARTS_WITH = enum.auto()
        DOMAIN_STARTS_WITHOUT = enum.auto()
        DOMAIN_ENDS_WITH = enum.auto()
        DOMAIN_ENDS_WITHOUT = enum.auto()
        DOMAIN_MATCH = enum.auto()
        ALL_IP_IN = enum.auto()
        ALL_IP_NOT_IN = enum.auto()
        ALL_IP_EQ = enum.auto()
        ALL_IP_NOT_EQ = enum.auto()
        ALL_GEOIP_EQ = enum.auto()
        ALL_GEOIP_NOT_EQ = enum.auto()
        ANY_IP_NOT_IN = enum.auto()
        ANY_IP_EQ = enum.auto()
        ANY_IP_NOT_EQ = enum.auto()
        ANY_GEOIP_EQ = enum.auto()
        ANY_GEOIP_NOT_EQ = enum.auto()
        NOT = enum.auto()
        AND = enum.auto()
        OR = enum.auto()

        def __repr__(self):
            return self.name

    class ExprAST:
        def __init__(self, ast, domain_required, ip_required, geoip_required):
            self.domain_required = domain_required
            self.ip_required = ip_required
            self.geoip_required = geoip_required
            self.ast = ast

        def __repr__(self):
            return repr(self.ast)

        @property
        def only_domain(self):
            return not (self.geoip_required or self.ip_required)

        def test(self, **context):
            OpCode = RuleIfParser.OpCode
            if self.domain_required:
                domain = context['domain']
            if self.ip_required:
                ips = context['ips']
            if self.geoip_required:
                geoips = context['geoips']
            def _test(ast):
                opcode = ast[0]
                if opcode == OpCode.AND:
                    return all(map(_test, ast[1]))
                elif opcode == OpCode.OR:
                    return any(map(_test, ast[1]))
                elif opcode == OpCode.NOT:
                    return not _test(ast[1])
                elif opcode == OpCode.DOMAIN_CONTAINS:
                    return ast[1].lower() in domain
                elif opcode == OpCode.DOMAIN_NOT_CONTAINS:
                    return ast[1].lower() not in domain
                elif opcode == OpCode.DOMAIN_EQ:
                    return ast[1].lower() == domain
                elif opcode == OpCode.DOMAIN_NOT_EQ:
                    return ast[1].lower() != domain
                elif opcode == OpCode.DOMAIN_STARTS_WITH:
                    return domain.startswith(ast[1].lower())
                elif opcode == OpCode.DOMAIN_STARTS_WITHOUT:
                    return not domain.startswith(ast[1].lower())
                elif opcode == OpCode.DOMAIN_ENDS_WITH:
                    return domain.endswith(ast[1].lower())
                elif opcode == OpCode.DOMAIN_ENDS_WITHOUT:
                    return not domain.endswith(ast[1].lower())
                elif opcode == OpCode.DOMAIN_MATCH:
                    return re.fullmatch(ast[1], domain) is not None
                elif opcode == OpCode.ALL_IP_IN:
                    return all(map(lambda ip: ip in ast[1], ips))
                elif opcode == OpCode.ALL_IP_NOT_IN:
                    return all(map(lambda ip: ip not in ast[1], ips))
                elif opcode == OpCode.ALL_IP_EQ:
                    return all(map(lambda ip: ip == ast[1], ips))
                elif opcode == OpCode.ALL_IP_NOT_EQ:
                    return all(map(lambda ip: ip != ast[1], ips))
                elif opcode == OpCode.ALL_GEOIP_EQ:
                    return all(map(lambda geoip: geoip == ast[1], geoips))
                elif opcode == OpCode.ALL_GEOIP_NOT_EQ:
                    return all(map(lambda geoip: geoip != ast[1], geoips))
                elif opcode == OpCode.ANY_IP_IN:
                    return any(map(lambda ip: ip in ast[1], ips))
                elif opcode == OpCode.ANY_IP_NOT_IN:
                    return any(map(lambda ip: ip not in ast[1], ips))
                elif opcode == OpCode.ANY_IP_EQ:
                    return any(map(lambda ip: ip == ast[1], ips))
                elif opcode == OpCode.ANY_IP_NOT_EQ:
                    return any(map(lambda ip: ip != ast[1], ips))
                elif opcode == OpCode.ANY_GEOIP_EQ:
                    return any(map(lambda geoip: geoip == ast[1], geoips))
                elif opcode == OpCode.ANY_GEOIP_NOT_EQ:
                    return any(map(lambda geoip: geoip != ast[1], geoips))
                return False
            return _test(self.ast)

    def __init__(self):
        self._domain_required = False
        self._ip_required = False
        self._geoip_required = False

        def _domain_op(op, token):
            self._domain_required = True
            return op, token

        def _ip_op(op, token):
            self._ip_required = True
            return op, token

        def _geoip_op(op, token):
            self._geoip_required = True
            return op, token

        def _and_op(op, tokens):
            return op, tuple(filter(lambda it: it != 'and', tokens))

        def _or_op(op, tokens):
            return op, tuple(filter(lambda it: it != 'or', tokens))

        self.parser = expr = pyparsing.Forward()
        domain_literal = pyparsing.Word(pyparsing.alphanums + '.-')\
            .set_name('domain')
        expr_domain_contains = (domain_literal + 'in domain')\
            .set_name('domain contains expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_CONTAINS, tokens[0]))
        expr_domain_not_contains = (domain_literal + 'not in domain')\
            .set_name('domain not contains expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_NOT_CONTAINS, tokens[0]))
        expr_domain_equal = ('domain is' + domain_literal)\
            .set_name('domain equal expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_EQ, tokens[1]))
        expr_domain_is_not = ('domain is not' + domain_literal)\
            .set_name('domain not equal expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_NOT_EQ, tokens[1]))
        expr_domain_starts_with = ('domain starts with' + domain_literal)\
            .set_name('domain starts with expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_STARTS_WITH, tokens[1]))
        expr_domain_starts_without = ('domain starts without' + domain_literal)\
            .set_name('domain starts without expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_STARTS_WITHOUT, tokens[1]))
        expr_domain_ends_with = ('domain ends with' + domain_literal)\
            .set_name('domain ends with expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_ENDS_WITH, tokens[1]))
        expr_domain_ends_without = ('domain ends without' + domain_literal)\
            .set_name('domain ends without expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_ENDS_WITHOUT, tokens[1]))
        expr_domain_match = ('domain match' + pyparsing.QuotedString('/'))\
            .set_name('domain match expression')\
            .set_parse_action(lambda tokens: _domain_op(self.OpCode.DOMAIN_MATCH, tokens[1]))
        _dec_num = pyparsing.Word(pyparsing.nums, max=3)
        ipv4_literal = _dec_num - ('.' + _dec_num) * 3
        ipv6_literal = pyparsing.Word(pyparsing.hexnums + ':.')
        ip_literal = pyparsing.Combine(ipv4_literal | ipv6_literal)\
            .set_name('ip address')\
            .set_parse_action(lambda tokens: ipaddress.ip_address(tokens[0]))
        ipv4_cidr_literal = ipv4_literal + '/' + pyparsing.Word(pyparsing.nums, max=2)
        ipv6_cidr_literal = ipv6_literal + '/' + pyparsing.Word(pyparsing.nums, max=3)
        ip_cidr_literal = pyparsing.Combine(ipv4_cidr_literal | ipv6_cidr_literal)\
            .set_name('ip cidr')\
            .set_parse_action(lambda tokens: netaddr.IPNetwork(tokens[0]))
        country_code_literal = pyparsing.Word(pyparsing.alphas, exact=2)
        expr_all_ip_in = ('all ip in' + ip_cidr_literal)\
            .set_name('all ip in cidr expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ALL_IP_IN, tokens[1]))
        expr_all_ip_not_in = ('all ip not in' + ip_cidr_literal)\
            .set_name('all ip not in cidr expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ALL_IP_NOT_IN, tokens[1]))
        expr_all_ip_equal = ('all ip is' + ip_literal)\
            .set_name('all ip equal expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ALL_IP_EQ, tokens[1]))
        expr_all_ip_not_equal = ('all ip is not' + ip_literal)\
            .set_name('all ip not equal expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ALL_IP_NOT_EQ, tokens[1]))
        expr_all_geoip_equal = ('all geoip is' + country_code_literal)\
            .set_name('all geoip equal expression')\
            .set_parse_action(lambda tokens: _geoip_op(self.OpCode.ALL_GEOIP_EQ, tokens[1]))
        expr_all_geoip_not_equal = ('all geoip is not' + country_code_literal)\
            .set_name('all geoip not equal expression')\
            .set_parse_action(lambda tokens: _geoip_op(self.OpCode.ALL_GEOIP_NOT_EQ, tokens[1]))
        expr_any_ip_in = ('any ip in' + ip_cidr_literal)\
            .set_name('any ip in cidr expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ANY_IP_IN, tokens[1]))
        expr_any_ip_not_in = ('any ip not in' + ip_cidr_literal)\
            .set_name('any ip not in cidr expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ANY_IP_NOT_IN, tokens[1]))
        expr_any_ip_equal = ('any ip is' + ip_literal)\
            .set_name('any ip equal expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ANY_IP_EQ, tokens[1]))
        expr_any_ip_not_equal = ('any ip is not' + ip_literal)\
            .set_name('any ip not equal expression')\
            .set_parse_action(lambda tokens: _ip_op(self.OpCode.ANY_IP_NOT_EQ, tokens[1]))
        expr_any_geoip_equal = ('any geoip is' + country_code_literal)\
            .set_name('any geoip equal expression')\
            .set_parse_action(lambda tokens: _geoip_op(self.OpCode.ANY_GEOIP_EQ, tokens[1]))
        expr_any_geoip_not_equal = ('any geoip is not' + country_code_literal)\
            .set_name('any geoip not equal expression')\
            .set_parse_action(lambda tokens: _geoip_op(self.OpCode.ANY_GEOIP_NOT_EQ, tokens[1]))
        expr_simple = (
            expr_domain_not_contains |
            expr_domain_contains |
            expr_domain_is_not |
            expr_domain_equal |
            expr_domain_starts_with |
            expr_domain_starts_without |
            expr_domain_ends_with |
            expr_domain_ends_without |
            expr_domain_match |
            expr_all_ip_in |
            expr_all_ip_not_in |
            expr_all_ip_equal |
            expr_all_ip_not_equal |
            expr_all_geoip_equal |
            expr_all_geoip_not_equal |
            expr_any_ip_in |
            expr_any_ip_not_in |
            expr_any_ip_equal |
            expr_any_ip_not_equal |
            expr_any_geoip_equal |
            expr_any_geoip_not_equal
        )
        expr <<= pyparsing.infix_notation(expr_simple, [
            ('not', 1, pyparsing.opAssoc.RIGHT, lambda tokens: (self.OpCode.NOT, tokens[0][1])),
            ('and', 2, pyparsing.opAssoc.LEFT, lambda tokens: _and_op(self.OpCode.AND, tokens[0])),
            ('or', 2, pyparsing.opAssoc.LEFT, lambda tokens: _or_op(self.OpCode.OR, tokens[0])),
        ])
    
    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        expr_ast = self.ExprAST(parse_results[0], 
                            self._domain_required, 
                            self._ip_required,
                            self._geoip_required)
        self._domain_required = False
        self._ip_required = False
        self._geoip_required = False
        return expr_ast


class RuleThenParser:
    '''
    阻止域名解析 block
    自定义域名解析结果 record.add, record.remove record.replace
    重定向到其他域名
    过滤（修改）返回的RR
    指定upstream
    '''
    class StmCode(enum.Enum):
        BLOCK = enum.auto()

    class StmAST:
        class Result:
            pass

        def __init__(self, ast):
            self.ast = ast

        def exec(self):
            return self.Result()

    def __init__(self):
        self.parser = stm = pyparsing.Forward()
        stm_block = pyparsing.Literal('block').set_name('block')\
            .set_parse_action(lambda _: self.StmCode.BLOCK)

    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return None


class RulesMiddleware(Middleware):
    def __init__(self, next, *rules):
        super().__init__(next)
        self.if_parser = RuleIfParser()
        self.then_parser = RuleThenParser()
        self.rules = dict(itertools.groupby(
            map(self._parse_rule, rules), 
            key=lambda if_then: 'pre' if if_then[0].only_domain else 'post'
        ))

    def _parse_rule(self, rule):
        try:
            return (
                self.if_parser.parse(rule['if']),
                self.then_parser.parse(rule['then'])
            )
        except pyparsing.exceptions.ParseException as exc:
            raise InvalidConfig('Invalid rules config: %s' % (exc, ))

    def _geoip(self, ip):
        with self.server.open_geoip() as reader:
            result = reader.get(ip_str)                            
        return result['country']['iso_code'] if result else None

    async def handle(self, request, **kwargs):
        domain = request.q.qname.idna().rstrip('.')
        for if_expr, then_stm in self.rules.get('pre', []):
            if if_expr.test(domain=domain):
                then_stm.exec()
                break
        response = await super().handle(request, **kwargs)
        ips = map(
            lambda r: str(r.rdata),
            filter(
                lambda r: r.rtype in (dnslib.QTYPE.AAAA, dnslib.QTYPE.A), 
                response.rr
            )
        )
        geoips = map(self._geoip, ips)
        for if_expr, then_stm in self.rules.get('post', []):
            if if_expr.test(domain=domain, ips=ips, geoips=geoips):
                then_stm.exec()
                break
        return response
