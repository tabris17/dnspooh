import unittest
import ipaddress

import dnslib

from dnspooh.middlewares.rules import RuleIfParser, RuleThenParser, RuleBeforeParser, RuleAfterParser, ReplacDomainHandler


if_parser = RuleIfParser()
then_parser = RuleThenParser()
before_parser = RuleBeforeParser()
after_parser = RuleAfterParser()


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


class RuleIfTest(unittest.TestCase):
    def test_in_domain(self):
        self.assertTrue(if_parser.parse('qq in domain').test('weixin.qq.com'))
        self.assertTrue(if_parser.parse('(qq, weibo) in domain').test('weixin.qq.com'))
        self.assertFalse(if_parser.parse('(qq, weibo) in domain').test('taobao.com'))

    def test_not_in_domain(self):
        self.assertFalse(if_parser.parse('qq not in domain').test('weixin.qq.com'))
        self.assertFalse(if_parser.parse('(qq, weibo) not in domain').test('weixin.qq.com'))
        self.assertTrue(if_parser.parse('(qq, weibo) not in domain').test('taobao.com'))

    def test_domain_is(self):
        self.assertTrue(if_parser.parse('domain is qq.com').test('qq.com'))
        self.assertTrue(if_parser.parse('domain is (baidu.com, taobao.com, weibo.com, qq.com)').test('qq.com'))
        self.assertFalse(if_parser.parse('domain is (baidu.com, taobao.com, weibo.com, qq.com)').test('tencent.com'))

    def test_domain_is_not(self):
        self.assertFalse(if_parser.parse('domain is not qq.com').test('qq.com'))
        self.assertFalse(if_parser.parse('domain is not (baidu.com, taobao.com, weibo.com, qq.com)').test('qq.com'))
        self.assertTrue(if_parser.parse('domain is not (baidu.com, taobao.com, weibo.com, qq.com)').test('tencent.com'))

    def test_domain_starts_with(self):
        self.assertTrue(if_parser.parse('domain starts with www').test('www.qq.com'))
        self.assertTrue(if_parser.parse('domain starts with (mobile, www, test)').test('www.qq.com'))
        self.assertFalse(if_parser.parse('domain starts with (mobile, www, test)').test('tencent.com'))

    def test_domain_starts_without(self):
        self.assertFalse(if_parser.parse('domain starts without www').test('www.qq.com'))
        self.assertFalse(if_parser.parse('domain starts without (mobile, www, test)').test('www.qq.com'))
        self.assertTrue(if_parser.parse('domain starts without (mobile, www, test)').test('tencent.com'))

    def test_domain_ends_with(self):
        self.assertTrue(if_parser.parse('domain ends with .com').test('www.qq.com'))
        self.assertTrue(if_parser.parse('domain ends with (.com, .cn, .com.cn)').test('www.qq.com'))
        self.assertFalse(if_parser.parse('domain ends with (.com, .cn, .com.cn)').test('mozilla.org'))

    def test_domain_ends_without(self):
        self.assertFalse(if_parser.parse('domain ends without .com').test('www.qq.com'))
        self.assertFalse(if_parser.parse('domain ends without (.com, .cn, .com.cn)').test('www.qq.com'))
        self.assertTrue(if_parser.parse('domain ends without (.com, .cn, .com.cn)').test('mozilla.org'))

    def test_domain_match(self):
        self.assertTrue(if_parser.parse('domain match /w+\.baidu\.com/').test('www.baidu.com'))
        self.assertFalse(if_parser.parse('domain match /w+\.baidu\.com/').test('baidu.com'))

    def test_not_and_or(self):
        self.assertTrue(if_parser.parse('domain is qq.com or domain ends with baidu.com and not qq in domain').test('www.baidu.com'))


class RuleThenTest(unittest.TestCase):
    def test_block(self):
        response = then_parser.parse('block').exec(dns_request('qq.com'))
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_return(self):
        response = then_parser.parse('return 127.0.0.1').exec(dns_request('qq.com'))
        record = response.rr[0]
        self.assertEqual(record.rtype, dnslib.QTYPE.A)
        self.assertEqual(str(record.rdata), '127.0.0.1')
        response = then_parser.parse('return (127.0.0.1, 127.0.0.2, 127.0.0.3)').exec(dns_request('qq.com'))
        self.assertEqual(response.header.a, 3)
        self.assertEqual(str(response.rr[0].rdata), '127.0.0.1')
        self.assertEqual(str(response.rr[1].rdata), '127.0.0.2')
        self.assertEqual(str(response.rr[2].rdata), '127.0.0.3')


class RuleBeforeTest(unittest.TestCase):
    def test_replace_domain(self):
        kwargs = dict()
        request = dns_request('baidu.com')
        after_handler = before_parser.parse('replace domain by google.com').exec(request, kwargs)
        self.assertTrue(isinstance(after_handler, ReplacDomainHandler))
        self.assertEqual(request.q.qname, 'google.com')
        response = after_handler.after_handle(dns_answer(request, '127.0.0.1'), None, None, None)
        self.assertEqual(response.q.qname, 'baidu.com')

    def test_set_upstream(self):
        kwargs = dict()
        request = dns_request('baidu.com')
        before_parser.parse('set upstream group to cn, set upstream name to cloudflare-tls').exec(request, kwargs)
        self.assertEqual(kwargs['upstream_group'], 'cn')
        self.assertEqual(kwargs['upstream_name'], 'cloudflare-tls')

    def test_set_proxy(self):
        proxy = 'socks5://127.0.0.0:1080'
        kwargs = dict()
        request = dns_request('baidu.com')
        before_parser.parse('set proxy on').exec(request, kwargs)
        self.assertTrue('proxy' not in kwargs)
        before_parser.parse('set proxy off').exec(request, kwargs)
        self.assertEqual(kwargs['proxy'], False)
        before_parser.parse('set proxy to ' + proxy).exec(request, kwargs)
        self.assertEqual(kwargs['proxy'], proxy)


def geoip(code):
    def _geoip(_):
        return code
    return _geoip


def ipaddr(record):
    ip_str = str(record.rdata)
    if record.rtype == dnslib.QTYPE.A:
        return ipaddress.IPv4Address(ip_str)
    elif record.rtype == dnslib.QTYPE.AAAA:
        return ipaddress.IPv6Address(ip_str)

def run(command):
    print('shell:', command)
    return

class RuleAfterTest(unittest.TestCase):
    def test_block_if(self):
        response = after_parser.parse('block if always').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_return_if(self):
        response = after_parser.parse('return 127.0.0.10 if always').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        record = response.rr[0]
        self.assertEqual(record.rtype, dnslib.QTYPE.A)
        self.assertEqual(str(record.rdata), '127.0.0.10')
        response = after_parser.parse('return (127.0.0.1, 127.0.0.2, 127.0.0.3) if always').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.a, 3)
        self.assertEqual(str(response.rr[0].rdata), '127.0.0.1')
        self.assertEqual(str(response.rr[1].rdata), '127.0.0.2')
        self.assertEqual(str(response.rr[2].rdata), '127.0.0.3')
    
    def test_add_record(self):
        response = after_parser.parse('add record (127.0.0.3, 127.0.0.4) if always').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        response = after_parser.parse('add record 127.0.0.5 if always').exec(response, geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.a, 5)
        self.assertEqual(str(response.rr[0].rdata), '127.0.0.1')
        self.assertEqual(str(response.rr[1].rdata), '127.0.0.2')
        self.assertEqual(str(response.rr[2].rdata), '127.0.0.3')
        self.assertEqual(str(response.rr[3].rdata), '127.0.0.4')
        self.assertEqual(str(response.rr[4].rdata), '127.0.0.5')

    def test_remove_record(self):
        response = after_parser.parse('remove record where ip is 127.0.0.1').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.a, 1)
        self.assertEqual(str(response.rr[0].rdata), '127.0.0.2')

    def test_replace_record(self):
        response = after_parser.parse('replace record by 192.168.1.1 where ip is 127.0.0.1').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.a, 2)
        self.assertEqual(str(response.rr[0].rdata), '192.168.1.1')
        self.assertEqual(str(response.rr[1].rdata), '127.0.0.2')

    def test_any_ip_is(self):
        response = after_parser.parse('block if any ip is 127.0.0.1').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if any ip is (127.0.0.1, 192.168.1.2)').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_any_ip_is_not(self):
        response = after_parser.parse('block if any ip is not 127.0.0.1').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if any ip is not (127.0.0.1, 127.0.0.3)').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_all_ip_is(self):
        response = after_parser.parse('block if all ip is 127.0.0.1').exec(dns_response('qq.com', '127.0.0.1'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if all ip is (127.0.0.1, 127.0.0.2)').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_all_ip_is_not(self):
        response = after_parser.parse('block if all ip is not 192.168.1.1').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if all ip is not (192.168.1.1, 192.168.1.2)').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_any_ip_in(self):
        response = after_parser.parse('block if any ip in 127.0.0.1/24').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if any ip in (127.0.0.1/24, 192.168.1.2/24)').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_any_ip_not_in(self):
        response = after_parser.parse('block if any ip not in 127.0.0.1/24').exec(dns_response('qq.com', '127.0.0.1', '172.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if any ip not in (127.0.0.1/24, 192.168.1.1/24)').exec(dns_response('qq.com', '127.0.0.1', '172.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_all_ip_in(self):
        response = after_parser.parse('block if all ip in 127.0.0.1/24').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if all ip in (127.0.0.1/24, 172.0.0.2/24)').exec(dns_response('qq.com', '127.0.0.1', '172.0.0.1'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_all_ip_not_in(self):
        response = after_parser.parse('block if all ip not in 192.168.1.1/24').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if all ip not in (192.168.1.1/24, 192.168.253.1/24)').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_geoip_is(self):
        response = after_parser.parse('block if any geoip is cn').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if all geoip is cn').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_geoip_is_not(self):
        response = after_parser.parse('block if any geoip is not cn').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('en'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)
        response = after_parser.parse('block if all geoip is not cn').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2'), geoip('en'), ipaddr, run)
        self.assertEqual(response.header.rcode, dnslib.RCODE.NXDOMAIN)

    def test_first_last(self):
        response = after_parser.parse('remove record where first or last').exec(dns_response('qq.com', '127.0.0.1', '127.0.0.2', '127.0.0.3'), geoip('cn'), ipaddr, run)
        self.assertEqual(response.header.a, 1)
        self.assertEqual(str(response.rr[0].rdata), '127.0.0.2')
