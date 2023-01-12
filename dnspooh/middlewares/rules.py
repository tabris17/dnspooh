import logging
import re
import enum
import ipaddress

import dnslib
import netaddr
import pyparsing

from . import Middleware
from exceptions import InvalidConfig


logger = logging.getLogger(__name__)


opt_comma = pyparsing.Suppress(pyparsing.Opt(','))
_dec_num = pyparsing.Word(pyparsing.nums, max=3)
_ipv4_literal = _dec_num - ('.' + _dec_num) * 3
_ipv6_literal = pyparsing.Word(pyparsing.hexnums + ':.')
_ipv4_cidr_literal = _ipv4_literal + '/' + pyparsing.Word(pyparsing.nums, max=2)
_ipv6_cidr_literal = _ipv6_literal + '/' + pyparsing.Word(pyparsing.nums, max=3)
ip_literal = pyparsing.Combine(_ipv4_literal | _ipv6_literal)\
    .set_name('ip address')\
    .set_parse_action(lambda tokens: ipaddress.ip_address(tokens[0]))
ip_cidr_literal = pyparsing.Combine(_ipv4_cidr_literal | _ipv6_cidr_literal)\
    .set_name('ip cidr')\
    .set_parse_action(lambda tokens: netaddr.IPNetwork(tokens[0]))
country_code_literal = pyparsing.Word(pyparsing.alphas, exact=2).set_name('country code')
domain_literal = pyparsing.Word(pyparsing.alphanums + '.-').set_name('domain')
ip_literal_list = (pyparsing.Suppress('(') + pyparsing.OneOrMore(ip_literal + opt_comma) + pyparsing.Suppress(')'))\
    .set_name('ip list')


def _and_op(op, tokens):
    return op, tuple(filter(lambda it: it != 'and', tokens))


def _or_op(op, tokens):
    return op, tuple(filter(lambda it: it != 'or', tokens))


class OpCode(enum.Enum):
    NOT = enum.auto()
    AND = enum.auto()
    OR = enum.auto()
    DOMAIN_CONTAINS = enum.auto()
    DOMAIN_NOT_CONTAINS = enum.auto()
    DOMAIN_EQ = enum.auto()
    DOMAIN_NOT_EQ = enum.auto()
    DOMAIN_STARTS_WITH = enum.auto()
    DOMAIN_STARTS_WITHOUT = enum.auto()
    DOMAIN_ENDS_WITH = enum.auto()
    DOMAIN_ENDS_WITHOUT = enum.auto()
    DOMAIN_MATCH = enum.auto()
    IP_IN = enum.auto()
    IP_NOT_IN = enum.auto()
    IP_EQ = enum.auto()
    IP_NOT_EQ = enum.auto()
    GEOIP_EQ = enum.auto()
    GEOIP_NOT_EQ = enum.auto()
    BLOCK = enum.auto()
    RETURN = enum.auto()
    RECORD_ADD = enum.auto()
    RECORD_REMOVE_IF = enum.auto()
    RECORD_REPLACE_IF = enum.auto()
    UPSTREAM_GROUP_SET = enum.auto()
    UPSTREAM_NAME_SET = enum.auto()
    DOMAIN_REPLACE = enum.auto()

    def __repr__(self):
        return self.name


class RuleIfParser:
    class ExprAST:
        def __init__(self, ast):
            self.ast = ast

        def __repr__(self):
            return repr(self.ast)

        def test(self, **context):
            domain = context['domain']
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
                return False
            return _test(self.ast)

    def __init__(self):
        self.parser = expr = pyparsing.Forward()
        expr_domain_contains = (domain_literal + 'in domain')\
            .set_name('domain contains expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_CONTAINS, tokens[0]))
        expr_domain_not_contains = (domain_literal + 'not in domain')\
            .set_name('domain not contains expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_NOT_CONTAINS, tokens[0]))
        expr_domain_equal = ('domain is' + domain_literal)\
            .set_name('domain equal expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_EQ, tokens[1]))
        expr_domain_is_not = ('domain is not' + domain_literal)\
            .set_name('domain not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_NOT_EQ, tokens[1]))
        expr_domain_starts_with = ('domain starts with' + domain_literal)\
            .set_name('domain starts with expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_STARTS_WITH, tokens[1]))
        expr_domain_starts_without = ('domain starts without' + domain_literal)\
            .set_name('domain starts without expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_STARTS_WITHOUT, tokens[1]))
        expr_domain_ends_with = ('domain ends with' + domain_literal)\
            .set_name('domain ends with expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_ENDS_WITH, tokens[1]))
        expr_domain_ends_without = ('domain ends without' + domain_literal)\
            .set_name('domain ends without expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_ENDS_WITHOUT, tokens[1]))
        expr_domain_match = ('domain match' + pyparsing.QuotedString('/'))\
            .set_name('domain match expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_MATCH, tokens[1]))
        expr_simple = (
            expr_domain_not_contains |
            expr_domain_contains |
            expr_domain_is_not |
            expr_domain_equal |
            expr_domain_starts_with |
            expr_domain_starts_without |
            expr_domain_ends_with |
            expr_domain_ends_without |
            expr_domain_match
        )
        expr <<= pyparsing.infix_notation(expr_simple, [
            ('not', 1, pyparsing.opAssoc.RIGHT, lambda tokens: (OpCode.NOT, tokens[0][1])),
            ('and', 2, pyparsing.opAssoc.LEFT, lambda tokens: _and_op(OpCode.AND, tokens[0])),
            ('or', 2, pyparsing.opAssoc.LEFT, lambda tokens: _or_op(OpCode.OR, tokens[0])),
        ])
    
    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return self.ExprAST(parse_results[0])


class RuleThenParser:
    class StmAST:
        class Result:
            pass

        def __repr__(self):
            return repr(self.ast)

        def __init__(self, ast):
            self.ast = list(ast)

        def exec(self):
            return self.Result()

    def __init__(self):
        upstream_name_literal = pyparsing.Word(pyparsing.alphanums + '.-_')\
            .set_name('upstream name')
        upstream_group_literal = pyparsing.Word(pyparsing.alphanums + '.-_')\
            .set_name('upstream group')
        expr_if = pyparsing.Forward()
        expr_ip_in = ('ip in' + ip_cidr_literal)\
            .set_name('ip in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_IN, tokens[1]))
        expr_ip_not_in = ('ip not in' + ip_cidr_literal)\
            .set_name('ip not in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_IP_NOT_IN, tokens[1]))
        expr_ip_equal = ('ip is' + ip_literal)\
            .set_name('ip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_EQ, tokens[1]))
        expr_ip_not_equal = ('ip is not' + ip_literal)\
            .set_name('ip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_NOT_EQ, tokens[1]))
        expr_geoip_equal = ('geoip is' + country_code_literal)\
            .set_name('geoip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.GEOIP_EQ, tokens[1]))
        expr_geoip_not_equal = ('geoip is not' + country_code_literal)\
            .set_name('geoip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.GEOIP_NOT_EQ, tokens[1]))
        expr_simple = (
            expr_ip_in |
            expr_ip_not_in |
            expr_ip_equal |
            expr_ip_not_equal |
            expr_geoip_equal |
            expr_geoip_not_equal
        )
        expr_if <<= pyparsing.infix_notation(expr_simple, [
            ('not', 1, pyparsing.opAssoc.RIGHT, lambda tokens: (OpCode.NOT, tokens[0][1])),
            ('and', 2, pyparsing.opAssoc.LEFT, lambda tokens: _and_op(OpCode.AND, tokens[0])),
            ('or', 2, pyparsing.opAssoc.LEFT, lambda tokens: _or_op(OpCode.OR, tokens[0])),
        ])
        stm_record_add = pyparsing.Group('add record')\
            .set_name('add record statement')
        stm_record_remove_if = pyparsing.Group('remove record if' + expr_if)\
            .set_name('remove record statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_REMOVE_IF, *tokens[0][1:]))
        stm_record_replace_if = pyparsing.Group('replace record by' + ip_literal + 'if' + expr_if)\
            .set_name('replace record statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_REPLACE_IF, tokens[0][3], tokens[0][1]))
        stm_upstream_name_set = ('set upstream name to' + upstream_name_literal)\
            .set_name('set upstream name statement')\
            .set_parse_action(lambda tokens: (OpCode.UPSTREAM_NAME_SET, tokens[1]))
        stm_upstream_group_set = ('set upstream group to' + upstream_group_literal)\
            .set_name('set upstream group statement')\
            .set_parse_action(lambda tokens: (OpCode.UPSTREAM_GROUP_SET, tokens[1]))
        stm_domain_replace = ('replace domain by' + domain_literal)\
            .set_name('replace domain statement')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_REPLACE, tokens[1]))
        stm_simple = (
            stm_record_add |
            stm_record_remove_if |
            stm_record_replace_if |
            stm_upstream_name_set |
            stm_upstream_group_set |
            stm_domain_replace
        )
        stm_block = pyparsing.Group('block')\
            .set_name('block statement')\
            .set_parse_action(lambda _: (OpCode.BLOCK, ))
        stm_return = pyparsing.Group('return' + ip_literal)\
            .set_name('return statement')\
            .set_parse_action(lambda tokens: (OpCode.RETURN, tokens[0][1]))
        stm_single = (
            stm_block |
            stm_return
        )
        self.parser = stm_single | pyparsing.OneOrMore(stm_simple + opt_comma)

    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return self.StmAST(parse_results)


class RulesMiddleware(Middleware):
    def __init__(self, next, *rules):
        super().__init__(next)
        self.if_parser = RuleIfParser()
        self.then_parser = RuleThenParser()
        self.rules = map(self._parse_rule, rules)

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
            result = reader.get(ip)                            
        return result['country']['iso_code'] if result else None

    async def handle(self, request, **kwargs):
        domain = request.q.qname.idna().rstrip('.')
        for if_expr, then_stm in self.rules:
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

        return response
