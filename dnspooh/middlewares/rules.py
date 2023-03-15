import asyncio
import logging
import re
import enum
import ipaddress
import functools
import subprocess

from collections.abc import Iterable

import dnslib
import pyparsing

from . import Middleware
from ..exceptions import InvalidConfig
from ..helpers import split_domain


logger = logging.getLogger(__name__)


opt_comma = pyparsing.Suppress(pyparsing.Opt(','))

_ipv4_literal = pyparsing.common.ipv4_address

_ipv6_literal = pyparsing.common.ipv6_address

_ipv4_cidr_literal = _ipv4_literal + '/' + pyparsing.Word(pyparsing.nums, max=2)

_ipv6_cidr_literal = _ipv6_literal + '/' + pyparsing.Word(pyparsing.nums, max=3)

ip_literal = pyparsing.Combine(_ipv4_literal | _ipv6_literal)\
    .set_name('ip address')\
    .set_parse_action(lambda tokens: ipaddress.ip_address(tokens[0]))

ip_cidr_literal = pyparsing.Combine(_ipv4_cidr_literal | _ipv6_cidr_literal)\
    .set_name('CIDR')\
    .set_parse_action(lambda tokens: ipaddress.ip_network(tokens[0], False))

ip_cidr_literal_list = (pyparsing.Suppress('(') + pyparsing.OneOrMore(ip_cidr_literal + opt_comma) + pyparsing.Suppress(')'))\
    .set_name('list of CIDRs')\
    .set_parse_action(lambda tokens: tuple(tokens))

country_code_literal = pyparsing.Word(pyparsing.alphas, exact=2).set_name('country code')

domain_literal = pyparsing.Word(pyparsing.alphanums + '.-').set_name('domain')\
    .set_parse_action(lambda tokens: tokens[0].lower())

domain_literal_set = (pyparsing.Suppress('(') + pyparsing.OneOrMore(domain_literal + opt_comma) + pyparsing.Suppress(')'))\
    .set_name('set of domains')\
    .set_parse_action(lambda tokens: set(map(lambda _: _.strip('.'), tokens)))

domain_literal_list = (pyparsing.Suppress('(') + pyparsing.OneOrMore(domain_literal + opt_comma) + pyparsing.Suppress(')'))\
    .set_name('list of domains')\
    .set_parse_action(lambda tokens: tuple(tokens))

ip_literal_list = (pyparsing.Suppress('(') + pyparsing.OneOrMore(ip_literal + opt_comma) + pyparsing.Suppress(')'))\
    .set_name('list of ip addresses')\
    .set_parse_action(lambda tokens: tuple(tokens))

ip_literal_set = (pyparsing.Suppress('(') + pyparsing.OneOrMore(ip_literal + opt_comma) + pyparsing.Suppress(')'))\
    .set_name('set of ip addresses')\
    .set_parse_action(lambda tokens: set(tokens))

proxy_literal = pyparsing.Regex(r'(http|socks5):\/\/([\w\.-:@%]+)').set_name('proxy')\
    .set_parse_action(lambda tokens: tokens[0])

always_literal = pyparsing.Literal('always').set_name('always')\
    .set_parse_action(lambda _: True)


def _and_op(op, tokens):
    return op, tuple(filter(lambda it: it != 'and', tokens))


def _or_op(op, tokens):
    return op, tuple(filter(lambda it: it != 'or', tokens))


def _response_add_answers(response, ip_addrs, top=False):
    hostname = response.q.qname.idna().rstrip('.')
    qtype = response.q.qtype
    if not isinstance(ip_addrs, Iterable):
        ip_addrs = (ip_addrs, )

    if qtype == dnslib.QTYPE.AAAA:
        records = [
            dnslib.RR(hostname, qtype, rdata=dnslib.AAAA(str(ip))) 
            for ip in ip_addrs if isinstance(ip, ipaddress.IPv6Address)
        ]
    elif qtype == dnslib.QTYPE.A:
        records = [
            dnslib.RR(hostname, qtype, rdata=dnslib.A(str(ip))) 
            for ip in ip_addrs if isinstance(ip, ipaddress.IPv4Address)
        ]
    else:
        return response
    if top:
        records.extend(response.rr)
        response.rr = records
        response.set_header_qa()
    else:
        response.add_answer(*records)
    return response


def _response_nxdomain(response):
    response.rr = []
    response.set_header_qa()
    response.header.rcode = dnslib.RCODE.NXDOMAIN
    return response


def _is_a_aaaa(request):
    return request.q.qtype in (dnslib.QTYPE.AAAA, dnslib.QTYPE.A)


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
    BLOCK = enum.auto()
    RETURN = enum.auto()
    UPSTREAM_GROUP_SET = enum.auto()
    UPSTREAM_NAME_SET = enum.auto()
    DOMAIN_REPLACE = enum.auto()
    PROXY_SET = enum.auto()
    FIRST = enum.auto()
    LAST = enum.auto()
    IP_IN = enum.auto()
    IP_NOT_IN = enum.auto()
    IP_EQ = enum.auto()
    IP_NOT_EQ = enum.auto()
    GEOIP_EQ = enum.auto()
    GEOIP_NOT_EQ = enum.auto()
    ANY_IP_IN = enum.auto()
    ANY_IP_NOT_IN = enum.auto()
    ANY_IP_EQ = enum.auto()
    ANY_IP_NOT_EQ = enum.auto()
    ANY_GEOIP_EQ = enum.auto()
    ANY_GEOIP_NOT_EQ = enum.auto()
    ALL_IP_IN = enum.auto()
    ALL_IP_NOT_IN = enum.auto()
    ALL_IP_EQ = enum.auto()
    ALL_IP_NOT_EQ = enum.auto()
    ALL_GEOIP_EQ = enum.auto()
    ALL_GEOIP_NOT_EQ = enum.auto()
    RECORD_ADD = enum.auto()
    RECORD_ADD_IF = enum.auto()
    RECORD_APPEND = enum.auto()
    RECORD_APPEND_IF = enum.auto()
    RECORD_INSERT = enum.auto()
    RECORD_INSERT_IF = enum.auto()
    RECORD_REMOVE_WHERE = enum.auto()
    RECORD_REPLACE_WHERE = enum.auto()
    RUN_WHERE = enum.auto()
    BLOCK_IF = enum.auto()
    RETURN_IF = enum.auto()

    def __repr__(self):
        return self.name


class RuleIfParser:
    class IfExpr:
        def __init__(self, ast):
            self.ast = ast

        def __repr__(self):
            return repr(self.ast)

        def test(self, domain):
            def _test(ast):
                if not isinstance(ast, tuple):
                    return ast
                opcode = ast[0]
                if opcode == OpCode.AND:
                    return all(map(_test, ast[1]))
                elif opcode == OpCode.OR:
                    return any(map(_test, ast[1]))
                elif opcode == OpCode.NOT:
                    return not _test(ast[1])
                elif opcode == OpCode.DOMAIN_CONTAINS:
                    if isinstance(ast[1], tuple):
                        return any(map(lambda _: _ in domain, ast[1]))
                    else:
                        return ast[1] in domain
                elif opcode == OpCode.DOMAIN_NOT_CONTAINS:
                    if isinstance(ast[1], tuple):
                        return all(map(lambda _: _ not in domain, ast[1]))
                    else:
                        return ast[1] not in domain
                elif opcode == OpCode.DOMAIN_EQ:
                    if isinstance(ast[1], set):
                        return domain in ast[1]
                    else:
                        return ast[1] == domain
                elif opcode == OpCode.DOMAIN_NOT_EQ:
                    if isinstance(ast[1], set):
                        return domain not in ast[1]
                    else:
                        return ast[1] != domain
                elif opcode == OpCode.DOMAIN_STARTS_WITH:
                    if isinstance(ast[1], set):
                        return any(map(lambda _: _ in ast[1], split_domain(domain, False)))
                    else:
                        return domain.startswith(ast[1])
                elif opcode == OpCode.DOMAIN_STARTS_WITHOUT:
                    if isinstance(ast[1], set):
                        return all(map(lambda _: _ not in ast[1], split_domain(domain, False)))
                    else:
                        return not domain.startswith(ast[1])
                elif opcode == OpCode.DOMAIN_ENDS_WITH:
                    if isinstance(ast[1], set):
                        return any(map(lambda _: _ in ast[1], split_domain(domain)))
                    else:
                        return domain.endswith(ast[1])
                elif opcode == OpCode.DOMAIN_ENDS_WITHOUT:
                    if isinstance(ast[1], set):
                        return all(map(lambda _: _ not in ast[1], split_domain(domain)))
                    else:
                        return not domain.endswith(ast[1])
                elif opcode == OpCode.DOMAIN_MATCH:
                    return re.fullmatch(ast[1], domain) is not None
                return False
            return _test(self.ast)

    def __init__(self):
        expr_domain_contains = ((domain_literal | domain_literal_list) + 'in domain')\
            .set_name('domain contains expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_CONTAINS, tokens[0]))
        expr_domain_not_contains = ((domain_literal | domain_literal_list) + 'not in domain')\
            .set_name('domain not contains expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_NOT_CONTAINS, tokens[0]))
        expr_domain_equal = ('domain is' + (domain_literal | domain_literal_set))\
            .set_name('domain equal expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_EQ, tokens[1]))
        expr_domain_not_equal = ('domain is not' + (domain_literal | domain_literal_set))\
            .set_name('domain not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_NOT_EQ, tokens[1]))
        expr_domain_starts_with = ('domain starts with' + (domain_literal | domain_literal_set))\
            .set_name('domain starts with expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_STARTS_WITH, tokens[1]))
        expr_domain_starts_without = ('domain starts without' + (domain_literal | domain_literal_set))\
            .set_name('domain starts without expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_STARTS_WITHOUT, tokens[1]))
        expr_domain_ends_with = ('domain ends with' + (domain_literal | domain_literal_set))\
            .set_name('domain ends with expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_ENDS_WITH, tokens[1]))
        expr_domain_ends_without = ('domain ends without' + (domain_literal | domain_literal_set))\
            .set_name('domain ends without expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_ENDS_WITHOUT, tokens[1]))
        expr_domain_match = ('domain match' + pyparsing.QuotedString('/'))\
            .set_name('domain match expression')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_MATCH, tokens[1]))
        expr_simple = (
            expr_domain_not_contains |
            expr_domain_contains |
            expr_domain_not_equal |
            expr_domain_equal |
            expr_domain_starts_without |
            expr_domain_starts_with |
            expr_domain_ends_without |
            expr_domain_ends_with |
            expr_domain_match
        )
        expr = pyparsing.Forward()
        expr <<= pyparsing.infix_notation(expr_simple, [
            ('not', 1, pyparsing.opAssoc.RIGHT, lambda tokens: (OpCode.NOT, tokens[0][1])),
            ('and', 2, pyparsing.opAssoc.LEFT, lambda tokens: _and_op(OpCode.AND, tokens[0])),
            ('or', 2, pyparsing.opAssoc.LEFT, lambda tokens: _or_op(OpCode.OR, tokens[0])),
        ])
        self.parser = expr | always_literal
    
    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return self.IfExpr(parse_results[0])


class RuleThenParser:
    class ThenExec:
        def __repr__(self):
            return repr(self.ast)

        def __init__(self, ast):
            self.ast = ast[0]

        def exec(self, request):
            response = request.reply()
            _exec = self.ast[0]
            if _exec == OpCode.BLOCK:
                response.header.rcode = dnslib.RCODE.NXDOMAIN
            elif _exec == OpCode.RETURN:
                ip_addrs = self.ast[1] if isinstance(self.ast[1], tuple) else (self.ast[1], )
                _response_add_answers(response, ip_addrs)
            return response

    def __init__(self):
        stm_block = pyparsing.Literal('block')\
            .set_name('block statement')\
            .set_parse_action(lambda _: (OpCode.BLOCK, ))
        stm_return = ('return' + (ip_literal_list | ip_literal))\
            .set_name('return statement')\
            .set_parse_action(lambda tokens: (OpCode.RETURN, tokens[1]))
        stm_single = (
            stm_block |
            stm_return
        )
        self.parser = stm_single

    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return self.ThenExec(parse_results)


class AfterHandler:
    def after_handle(self, response, geoip, ipaddr, run):
        return response


class ReplacDomainHandler(AfterHandler):
    def __init__(self, domain):
        self.domain = domain

    def after_handle(self, response, geoip, ipaddr, run):
        response.q.qname = self.domain
        return response


class AfterHandlerList:
    def __init__(self):
        self.handlers = []

    def join(self, handler):
        if handler is None or not hasattr(handler, 'after_handle'):
            return self
        self.handlers.append(handler)
        return self

    def after_handle(self, response, geoip, ipaddr, run):
        for handler in self.handlers:
            response = handler.after_handle(response, geoip, ipaddr, run)
        return response


class RuleBeforeParser:
    class BeforeExec:
        def __repr__(self):
            return repr(self.ast)

        def __init__(self, ast):
            self.ast = list(ast)

        def exec(self, request, kwargs):
            after_handler = None
            for stm in self.ast:
                _exec = stm[0]
                if _exec == OpCode.UPSTREAM_GROUP_SET:
                    kwargs['upstream_group'] = stm[1]
                elif _exec == OpCode.UPSTREAM_NAME_SET:
                    kwargs['upstream_name'] = stm[1]
                elif _exec == OpCode.DOMAIN_REPLACE:
                    after_handler = ReplacDomainHandler(request.q.qname)
                    request.q.qname = stm[1]
                elif _exec == OpCode.PROXY_SET:
                    if stm[1] == 'on':
                        kwargs.pop('proxy', None)
                    elif stm[1] == 'off':
                        kwargs['proxy'] = None
                    else:
                        kwargs['proxy'] = stm[1]
            return after_handler

    def __init__(self):
        upstream_name_literal = pyparsing.Word(pyparsing.alphanums + '.-_')\
            .set_name('upstream name')
        upstream_group_literal = pyparsing.Word(pyparsing.alphanums + '.-_')\
            .set_name('upstream group')
        stm_upstream_name_set = ('set upstream name to' + upstream_name_literal)\
            .set_name('set upstream name statement')\
            .set_parse_action(lambda tokens: (OpCode.UPSTREAM_NAME_SET, tokens[1]))
        stm_upstream_group_set = ('set upstream group to' + upstream_group_literal)\
            .set_name('set upstream group statement')\
            .set_parse_action(lambda tokens: (OpCode.UPSTREAM_GROUP_SET, tokens[1]))
        stm_domain_replace = ('replace domain by' + domain_literal)\
            .set_name('replace domain statement')\
            .set_parse_action(lambda tokens: (OpCode.DOMAIN_REPLACE, tokens[1]))
        stm_proxy_on = pyparsing.Literal('set proxy on')\
            .set_name('set proxy on statement')\
            .set_parse_action(lambda _: (OpCode.PROXY_SET, 'on'))
        stm_proxy_off = pyparsing.Literal('set proxy off')\
            .set_name('set proxy off statement')\
            .set_parse_action(lambda _: (OpCode.PROXY_SET, 'off'))
        stm_proxy_set = ('set proxy to' + proxy_literal)\
            .set_name('set proxy to statement')\
            .set_parse_action(lambda tokens: (OpCode.PROXY_SET, tokens[1]))
        stm_simple = (
            stm_upstream_name_set |
            stm_upstream_group_set |
            stm_domain_replace |
            stm_proxy_on |
            stm_proxy_off |
            stm_proxy_set
        )
        self.parser = pyparsing.OneOrMore(stm_simple + opt_comma)

    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return self.BeforeExec(parse_results)


class RuleAfterParser:
    class AfterExec:
        def __init__(self, ast):
            self.ast = list(ast)

        def __repr__(self):
            return repr(self.ast)

        def test_record(self, geoip, ipaddr, response, expr_if, idx_rr):
            idx, rr = idx_rr
            def test(ast):
                if not isinstance(ast, tuple):
                    return ast
                if rr.rtype not in (dnslib.QTYPE.AAAA, dnslib.QTYPE.A):
                    return False

                opcode = ast[0]
                if opcode == OpCode.AND:
                    return all(map(test, ast[1]))
                elif opcode == OpCode.OR:
                    return any(map(test, ast[1]))
                elif opcode == OpCode.NOT:
                    return not test(ast[1])
                elif opcode == OpCode.IP_EQ:
                    if isinstance(ast[1], set):
                        return ipaddr(rr) in ast[1]
                    else:
                        return ast[1] == ipaddr(rr)
                elif opcode == OpCode.IP_NOT_EQ:
                    if isinstance(ast[1], set):
                        return ipaddr(rr) not in ast[1]
                    else:
                        return ast[1] != ipaddr(rr)
                elif opcode == OpCode.IP_IN:
                    if isinstance(ast[1], tuple):
                        return any(map(lambda _: ipaddr(rr) in _, ast[1]))
                    else:
                        return ipaddr(rr) in ast[1]
                elif opcode == OpCode.IP_NOT_IN:
                    if isinstance(ast[1], tuple):
                        return all(map(lambda _: ipaddr(rr) not in _, ast[1]))
                    else:
                        return ipaddr(rr) not in ast[1]
                elif opcode == OpCode.GEOIP_EQ:
                    return geoip(rr) == ast[1].upper()
                elif opcode == OpCode.GEOIP_NOT_EQ:
                    return geoip(rr) != ast[1].upper()
                elif opcode == OpCode.FIRST:
                    return idx == 0
                elif opcode == OpCode.LAST:
                    return idx == len(response.rr) - 1
                return False
            return test(expr_if)

        def test_response(self, geoip, ipaddr, expr_if, response):
            def test(ast):
                if not isinstance(ast, tuple):
                    return ast

                opcode = ast[0]
                if opcode == OpCode.AND:
                    return all(map(test, ast[1]))
                elif opcode == OpCode.OR:
                    return any(map(test, ast[1]))
                elif opcode == OpCode.NOT:
                    return not test(ast[1])

                rr = filter(lambda rr: rr.rtype in (dnslib.QTYPE.AAAA, dnslib.QTYPE.A), response.rr)
                ip_addresses = map(lambda rr: ipaddr(rr), rr)
                country_codes = map(lambda rr: geoip(rr), rr)
                if opcode == OpCode.ANY_IP_EQ:
                    if isinstance(ast[1], set):
                        return any(map(lambda _: _ in ast[1], ip_addresses))
                    else:
                        return any(map(lambda ip: ip == ast[1], ip_addresses))
                elif opcode == OpCode.ANY_IP_NOT_EQ:
                    if isinstance(ast[1], set):
                        return any(map(lambda _: _ not in ast[1], ip_addresses))
                    else:
                        return any(map(lambda ip: ip != ast[1], ip_addresses))
                elif opcode == OpCode.ANY_IP_IN:
                    if isinstance(ast[1], tuple):
                        return any(map(lambda ip: any(map(lambda _: ip in _, ast[1])), ip_addresses))
                    else:
                        return any(map(lambda ip: ip in ast[1], ip_addresses))
                elif opcode == OpCode.ANY_IP_NOT_IN:
                    if isinstance(ast[1], tuple):
                        return any(map(lambda ip: all(map(lambda _: ip not in _, ast[1])), ip_addresses))
                    else:
                        return any(map(lambda ip: ip not in ast[1], ip_addresses))
                elif opcode == OpCode.ANY_GEOIP_EQ:
                    return any(map(lambda country_code: country_code == ast[1], country_codes))
                elif opcode == OpCode.ANY_GEOIP_NOT_EQ:
                    return any(map(lambda country_code: country_code != ast[1], country_codes))
                elif opcode == OpCode.ALL_IP_EQ:
                    if isinstance(ast[1], set):
                        return all(map(lambda _: _ in ast[1], ip_addresses))
                    else:
                        return all(map(lambda ip: ip == ast[1], ip_addresses))
                elif opcode == OpCode.ALL_IP_NOT_EQ:
                    if isinstance(ast[1], set):
                        return all(map(lambda _: _ not in ast[1], ip_addresses))
                    else:
                        return all(map(lambda ip: ip != ast[1], ip_addresses))
                elif opcode == OpCode.ALL_IP_IN:
                    if isinstance(ast[1], tuple):
                        return all(map(lambda ip: any(map(lambda _: ip in _, ast[1])), ip_addresses))
                    else:
                        return all(map(lambda ip: ip in ast[1], ip_addresses))
                elif opcode == OpCode.ALL_IP_NOT_IN:
                    if isinstance(ast[1], tuple):
                        return all(map(lambda ip: all(map(lambda _: ip not in _, ast[1])), ip_addresses))
                    else:
                        return all(map(lambda ip: ip not in ast[1], ip_addresses))
                elif opcode == OpCode.ALL_GEOIP_EQ:
                    return all(map(lambda country_code: country_code == ast[1], country_codes))
                elif opcode == OpCode.ALL_GEOIP_NOT_EQ:
                    return all(map(lambda country_code: country_code != ast[1], country_codes))
                return False
            return test(expr_if)

        def exec(self, response, geoip, ipaddr, run):
            test_record = functools.partial(self.test_record, geoip, ipaddr, response)
            test_response = functools.partial(self.test_response, geoip, ipaddr)

            for stm in self.ast:
                _exec = stm[0]
                if _exec in (OpCode.RECORD_ADD, OpCode.RECORD_APPEND):
                    _response_add_answers(response, stm[1])
                    continue
                elif _exec == OpCode.RECORD_INSERT:
                    _response_add_answers(response, stm[1], True)
                    continue

                expr_if = stm[1]
                if _exec == OpCode.RECORD_REMOVE_WHERE:
                    response.rr = list(map(
                        lambda idx_rr: idx_rr[1],
                        filter(
                            lambda idx_rr: not test_record(expr_if, idx_rr), 
                            enumerate(response.rr)
                        )
                    ))
                    response.set_header_qa()
                    continue
                elif _exec == OpCode.RECORD_REPLACE_WHERE:
                    qtype = response.q.qtype
                    ip = stm[2]
                    for idx, rr in enumerate(response.rr):
                        if not test_record(expr_if, (idx, rr)):
                            continue
                        if isinstance(ip, ipaddress.IPv6Address) and qtype == dnslib.QTYPE.AAAA:
                            rr.rdata = dnslib.AAAA(str(ip))
                        elif isinstance(ip, ipaddress.IPv4Address) and qtype == dnslib.QTYPE.A:
                            rr.rdata = dnslib.A(str(ip))
                    continue
                elif _exec == OpCode.RUN_WHERE:
                    cmd = stm[2]
                    hostname = response.q.qname.idna().rstrip('.')
                    for idx, rr in enumerate(response.rr):
                        if not test_record(expr_if, (idx, rr)):
                            continue
                        run(cmd.format(ip=rr.rdata, domain=hostname))
                    continue

                if _exec == OpCode.RETURN_IF:
                    if test_response(expr_if, response):
                        response.rr = []
                        _response_add_answers(response, stm[2])
                elif _exec == OpCode.BLOCK_IF:
                    if test_response(expr_if, response):
                        _response_nxdomain(response)
                elif _exec in (OpCode.RECORD_ADD_IF, OpCode.RECORD_APPEND_IF):
                    if test_response(expr_if, response):
                        _response_add_answers(response, stm[2])
                elif _exec == OpCode.RECORD_INSERT_IF:
                    if test_response(expr_if, response):
                        _response_add_answers(response, stm[2], True)
            return response

    def __init__(self):
        expr_first = pyparsing.Literal('first').set_name('first')\
            .set_parse_action(lambda _: (OpCode.FIRST, ))
        expr_last = pyparsing.Literal('last').set_name('last')\
            .set_parse_action(lambda _: (OpCode.LAST, ))
        expr_ip_in = ('ip in' + (ip_cidr_literal | ip_cidr_literal_list))\
            .set_name('ip in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_IN, tokens[1]))
        expr_ip_not_in = ('ip not in' + (ip_cidr_literal | ip_cidr_literal_list))\
            .set_name('ip not in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_NOT_IN, tokens[1]))
        expr_ip_equal = ('ip is' + (ip_literal | ip_literal_set))\
            .set_name('ip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_EQ, tokens[1]))
        expr_ip_not_equal = ('ip is not' + (ip_literal | ip_literal_set))\
            .set_name('ip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.IP_NOT_EQ, tokens[1]))
        expr_geoip_equal = ('geoip is' + country_code_literal)\
            .set_name('geoip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.GEOIP_EQ, tokens[1]))
        expr_geoip_not_equal = ('geoip is not' + country_code_literal)\
            .set_name('geoip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.GEOIP_NOT_EQ, tokens[1]))
        expr_any_ip_in = ('any ip in' + (ip_cidr_literal | ip_cidr_literal_list))\
            .set_name('any ip in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.ANY_IP_IN, tokens[1]))
        expr_any_ip_not_in = ('any ip not in' + (ip_cidr_literal | ip_cidr_literal_list))\
            .set_name('any ip not in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.ANY_IP_NOT_IN, tokens[1]))
        expr_any_ip_equal = ('any ip is' + (ip_literal | ip_literal_set))\
            .set_name('any ip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ANY_IP_EQ, tokens[1]))
        expr_any_ip_not_equal = ('any ip is not' + (ip_literal | ip_literal_set))\
            .set_name('any ip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ANY_IP_NOT_EQ, tokens[1]))
        expr_any_geoip_equal = ('any geoip is' + country_code_literal)\
            .set_name('any geoip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ANY_GEOIP_EQ, tokens[1]))
        expr_any_geoip_not_equal = ('any geoip is not' + country_code_literal)\
            .set_name('any geoip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ANY_GEOIP_NOT_EQ, tokens[1]))
        expr_all_ip_in = ('all ip in' + (ip_cidr_literal | ip_cidr_literal_list))\
            .set_name('all ip in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_IP_IN, tokens[1]))
        expr_all_ip_not_in = ('all ip not in' + (ip_cidr_literal | ip_cidr_literal_list))\
            .set_name('all ip not in cidr expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_IP_NOT_IN, tokens[1]))
        expr_all_ip_equal = ('all ip is' + (ip_literal | ip_literal_set))\
            .set_name('all ip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_IP_EQ, tokens[1]))
        expr_all_ip_not_equal = ('all ip is not' + (ip_literal | ip_literal_set))\
            .set_name('all ip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_IP_NOT_EQ, tokens[1]))
        expr_all_geoip_equal = ('all geoip is' + country_code_literal)\
            .set_name('all geoip equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_GEOIP_EQ, tokens[1]))
        expr_all_geoip_not_equal = ('all geoip is not' + country_code_literal)\
            .set_name('all geoip not equal expression')\
            .set_parse_action(lambda tokens: (OpCode.ALL_GEOIP_NOT_EQ, tokens[1]))
        expr_simple = (
            expr_first |
            expr_last |
            expr_ip_not_in |
            expr_ip_in |
            expr_ip_not_equal |
            expr_ip_equal |
            expr_geoip_not_equal |
            expr_geoip_equal
        )
        expr_complex = (
            expr_any_ip_in |
            expr_any_ip_not_in |
            expr_any_ip_equal |
            expr_any_ip_not_equal |
            expr_any_geoip_not_equal |
            expr_any_geoip_equal |
            expr_all_ip_in |
            expr_all_ip_not_in |
            expr_all_ip_equal |
            expr_all_ip_not_equal |
            expr_all_geoip_not_equal |
            expr_all_geoip_equal
        )
        expr_if = pyparsing.Forward()
        expr_if <<= (pyparsing.infix_notation(expr_complex, [
            ('not', 1, pyparsing.opAssoc.RIGHT, lambda tokens: (OpCode.NOT, tokens[0][1])),
            ('and', 2, pyparsing.opAssoc.LEFT, lambda tokens: _and_op(OpCode.AND, tokens[0])),
            ('or', 2, pyparsing.opAssoc.LEFT, lambda tokens: _or_op(OpCode.OR, tokens[0])),
        ]) | always_literal)
        expr_where = pyparsing.Forward()
        expr_where <<= (pyparsing.infix_notation(expr_simple, [
            ('not', 1, pyparsing.opAssoc.RIGHT, lambda tokens: (OpCode.NOT, tokens[0][1])),
            ('and', 2, pyparsing.opAssoc.LEFT, lambda tokens: _and_op(OpCode.AND, tokens[0])),
            ('or', 2, pyparsing.opAssoc.LEFT, lambda tokens: _or_op(OpCode.OR, tokens[0])),
        ]) | always_literal)
        stm_record_add = ('add record' + (ip_literal | ip_literal_list))\
            .set_name('add record statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_ADD, tokens[1]))
        stm_record_add_if = ('add record' + (ip_literal | ip_literal_list) + 'if' + expr_if)\
            .set_name('add record if statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_ADD_IF, tokens[3], tokens[1]))
        stm_record_append = ('append record' + (ip_literal | ip_literal_list))\
            .set_name('append record statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_APPEND, tokens[1]))
        stm_record_append_if = ('append record' + (ip_literal | ip_literal_list) + 'if' + expr_if)\
            .set_name('append record if statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_APPEND_IF, tokens[3], tokens[1]))
        stm_record_insert = ('insert record' + (ip_literal | ip_literal_list))\
            .set_name('insert record statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_INSERT, tokens[1]))
        stm_record_insert_if = ('insert record' + (ip_literal | ip_literal_list) + 'if' + expr_if)\
            .set_name('insert record if statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_INSERT_IF, tokens[3], tokens[1]))
        stm_record_remove_where = ('remove record where' + expr_where)\
            .set_name('remove record where statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_REMOVE_WHERE, *tokens[1:]))
        stm_record_replace_where = ('replace record by' + ip_literal + 'where' + expr_where)\
            .set_name('replace record where statement')\
            .set_parse_action(lambda tokens: (OpCode.RECORD_REPLACE_WHERE, tokens[3], tokens[1]))
        stm_run_command_where = ('run' + pyparsing.QuotedString('"') + 'where' + expr_where)\
            .set_name('run command where statement')\
            .set_parse_action(lambda tokens: (OpCode.RUN_WHERE, tokens[3], tokens[1]))
        stm_simple = (
            stm_record_add_if |
            stm_record_add |
            stm_record_append_if |
            stm_record_append |
            stm_record_insert_if |
            stm_record_insert |
            stm_record_remove_where |
            stm_record_replace_where |
            stm_run_command_where
        )
        stm_block_if = ('block if' + expr_if)\
            .set_name('block if statement')\
            .set_parse_action(lambda tokens: (OpCode.BLOCK_IF, tokens[1]))
        stm_return_if = ('return' + (ip_literal_list | ip_literal) + 'if' + expr_if)\
            .set_name('return if statement')\
            .set_parse_action(lambda tokens: (OpCode.RETURN_IF, tokens[3], tokens[1]))
        stm_single = (
            stm_block_if |
            stm_return_if
        )
        self.parser = stm_single | pyparsing.OneOrMore(stm_simple + opt_comma)

    def parse(self, source):
        parse_results = self.parser.parse_string(source, parse_all=True)
        return self.AfterExec(parse_results)


class RulesMiddleware(Middleware):
    class Rule:
        def test(self, domain):
            return self.if_expr.test(domain)

    class IfThenRule(Rule):
        def __init__(self, if_expr, then_exec, is_ended):
            self.if_expr = if_expr
            self.then_exec = then_exec
            self.is_ended = is_ended

        def exec(self, request):
            return self.then_exec.exec(request)

    class IfBeforeRule(Rule):
        def __init__(self, if_expr, before, is_ended):
            self.if_expr = if_expr
            self.before = before
            self.is_ended = is_ended

        def before_handle(self, request, kwargs):
            return self.before.exec(request, kwargs)

    class IfAfterRule(Rule):
        def __init__(self, if_expr, after, is_ended):
            self.if_expr = if_expr
            self.after = after
            self.is_ended = is_ended

        def after_handle(self, response, geoip, ipaddr, run):
            return self.after.exec(response, geoip, ipaddr, run)

    class IfBeforeAfterRule(IfBeforeRule, IfAfterRule):
        def __init__(self, if_expr, before, after, is_ended):
            self.if_expr = if_expr
            self.before = before
            self.after = after
            self.is_ended = is_ended

    def __init__(self, *rules):
        self.if_parser = RuleIfParser()
        self.then_parser = RuleThenParser()
        self.before_parser = RuleBeforeParser()
        self.after_parser = RuleAfterParser()
        self.rules = [self._parse_rule(rule) for rule in rules]

    def _parse_rule(self, rule):
        if 'end' not in rule:
            rule['end'] = False
        try:
            len_of_rule = len(rule)
            if len_of_rule == 3:
                if 'then' in rule:
                    return self.IfThenRule(
                        self.if_parser.parse(rule['if']),
                        self.then_parser.parse(rule['then']),
                        rule['end']
                    )
                elif 'before' in rule:
                    return self.IfBeforeRule(
                        self.if_parser.parse(rule['if']),
                        self.before_parser.parse(rule['before']),
                        rule['end']
                    )
                else:
                    return self.IfAfterRule(
                        self.if_parser.parse(rule['if']),
                        self.after_parser.parse(rule['after']),
                        rule['end']
                    )
            elif len_of_rule == 4:
                return self.IfBeforeAfterRule(
                    self.if_parser.parse(rule['if']),
                    self.before_parser.parse(rule['before']),
                    self.after_parser.parse(rule['after']),
                    rule['end']
                )
            raise KeyError()
        except pyparsing.exceptions.ParseException as exc:
            raise InvalidConfig('Invalid rules config: %s' % (exc, ))
        except KeyError:
            raise InvalidConfig('A rule must match [if/then] or [if/before/after] pattern')

    def _geoip(self, ip):
        result = self.geoip_reader.get(ip)                            
        return result['country']['iso_code'] if result else None

    async def _query(self, request, **kwargs):
        response = await super().handle(request, **kwargs)
        ips = map(lambda r: str(r.rdata), response.rr)
        geoips = map(self._geoip, ips)
        return response, ips, geoips

    @property
    def geoip_reader(self):
        if not hasattr(self, '_geoip_reader'):
            self._geoip_reader = self.server.open_geoip()
        return self._geoip_reader

    async def handle(self, request, **kwargs):
        cached_geoips = dict()
        cached_ipaddrs = dict()
        def geoip(record):
            ip_str = str(record.rdata)
            if ip_str in cached_geoips:
                return cached_geoips[ip_str]
            cached_geoips[ip_str] = country_code = self._geoip(ip_str)
            return country_code
        
        def ipaddr(record):
            ip_str = str(record.rdata)
            if ip_str in cached_ipaddrs:
                return cached_ipaddrs[ip_str]
            if record.rtype == dnslib.QTYPE.A:
                return ipaddress.IPv4Address(ip_str)
            elif record.rtype == dnslib.QTYPE.AAAA:
                return ipaddress.IPv6Address(ip_str)

        def run(command):
            logger.debug('Shell: %s', command)
            return self.server.create_task(
                asyncio.create_subprocess_shell(
                    command, 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                ), 
                command
            )

        response = None
        after_handlers = AfterHandlerList()
        domain = request.q.qname.idna().rstrip('.')
        for rule in self.rules:
            if not rule.test(domain): continue

            rule_type = type(rule)
            if rule_type == self.IfThenRule:
                if response is None:
                    response = rule.exec(request)
            elif rule_type == self.IfBeforeRule:
                if response is None:
                    after_handlers.join(rule.before_handle(request, kwargs))
            elif rule_type == self.IfAfterRule:
                after_handlers.join(rule)
            elif rule_type == self.IfBeforeAfterRule:
                if response is None:
                    after_handlers.join(rule.before_handle(request, kwargs))
                after_handlers.join(rule)
            if rule.is_ended: break

        if response is None:
            response = await super().handle(request, **kwargs)
        return after_handlers.after_handle(response, geoip, ipaddr, run)
