import base64
import struct
import ipaddress

from urllib.parse import urlsplit

from .helpers import s_addr, Scheme


DEFAULT_HTTP_PROXY_PORT = 8080

DEFAULT_SOCKS5_PROXY_PORT = 1080

class Proxy:
    def __init__(self, url, hostname, port, host=None, username=None, password=None):
        self.url = url
        self.hostname = hostname
        self.port = port
        self.host = host
        self.username = username
        self.password = password

    def __repr__(self):
        return self.url
    
    def to_json(self):
        return self.__repr__()

    def has_auth(self):
        return self.username is not None and \
               self.password is not None

    def udp_tunnel_enabled(self):
        return False

    async def handshake(self, reader, writer, remote_addr):
        raise NotImplementedError()


class HttpProxy(Proxy):
    async def handshake(self, reader, writer, remote_addr):
        if self.has_auth():
            credentials = base64.b64encode(
                ('%s:%s' % (self.username, self.password)).encode()
            ).decode()
            request = 'CONNECT %s:%s HTTP/1.1\r\n' % remote_addr
            request += 'Proxy-Authorization: basic %s\r\n\r\n' % (credentials, )
        else:
            request = 'CONNECT %s:%s HTTP/1.1\r\n\r\n' % remote_addr

        writer.write(request.encode())
        await writer.drain()
        response = await reader.readuntil(b'\r\n\r\n')
        return response.startswith(b'HTTP/1.1 200')


class Socks5Proxy(Proxy):
    VERSION = 5

    AUTH_METHOD = 2

    NONE_METHOD = 0

    AUTH_SUCCESS = 0

    CMD_CONNECT = 1

    CMD_UDP_ASSOCIATE = 3

    ATYP_IPV4 = 1

    ATYP_IPV6 = 4

    REP_SUCCESS = 0

    class UDPTunnel:
        def __init__(self, addr):
            self.addr = addr

        def parse(self, data, src_addr):
            _, _, atype = struct.unpack('!H2B', data[:4])
            if atype == Socks5Proxy.ATYP_IPV4:
                _from_addr, from_port = struct.unpack('!4sH', data[4:10])
                from_addr = (str(ipaddress.IPv4Address(_from_addr)), from_port)
                entity_data = data[10:]
            elif atype == Socks5Proxy.ATYP_IPV6:
                _from_addr, from_port = struct.unpack('!16sH', data[4:22])
                from_addr = (str(ipaddress.IPv6Address(_from_addr)), from_port)
                entity_data = data[22:]
            else:
                raise ValueError('Invalid ATYPE %d received' % atype)
            if from_addr != src_addr:
                raise ValueError('Source address %s does not match' % s_addr(from_addr))

            return entity_data

        def pack(self, data, dst_addr):
            ip, port = dst_addr
            ip_addr = ipaddress.ip_address(ip)
            if isinstance(ip_addr, ipaddress.IPv4Address):
                pack_header = struct.pack(
                    '!H2B4sH', 0, 0, 
                    Socks5Proxy.ATYP_IPV4,
                    ip_addr.packed, 
                    port
                )
            elif isinstance(ip_addr, ipaddress.IPv6Address):
                pack_header = struct.pack(
                    '!H2B16sH', 0, 0, 
                    Socks5Proxy.ATYP_IPV6,
                    ip_addr.packed, 
                    port
                )
            else:
                raise ValueError('Invalid destination address "%s"' % ip)

            return pack_header + data

    def udp_tunnel_enabled(self):
        return True

    async def _handshake(self, reader, writer, remote_addr, scheme=Scheme.TCP):
        writer.write(struct.pack('!3B', self.VERSION, 1, self.AUTH_METHOD))
        await writer.drain()
        server_version, method = struct.unpack('!2B', await reader.readexactly(2))
        if server_version != self.VERSION:
            raise ConnectionError('Unsupported socks proxy version %d' % (server_version, ))
        if method != self.NONE_METHOD:
            if not self.has_auth():
                raise ConnectionError('Proxy "%s" need authentication' % (self.url, ))
            if method != self.AUTH_METHOD:
                raise ConnectionError('Unsupported socks proxy authentication method %d' % (method, ))

            username = self.username.encode()
            password = self.password.encode()
            username_len = len(username)
            password_len = len(password)
            writer.write(struct.pack(
                '!2B%dsB%ds' % (username_len, password_len), 
                self.VERSION, 
                username_len,
                username,
                password_len,
                password
            ))
            await writer.drain()
            method, status = struct.unpack('!2B', await reader.readexactly(2))
            if status != self.AUTH_SUCCESS:
                raise ConnectionError('Socks proxy authentication failed')

        dst_addr, dst_port = remote_addr
        ip_addr = ipaddress.ip_address(dst_addr)
        if isinstance(ip_addr, ipaddress.IPv4Address):
            writer.write(struct.pack(
                '!4B4sH', 
                self.VERSION, 
                self.CMD_CONNECT if scheme == Scheme.TCP else self.CMD_UDP_ASSOCIATE,
                0, 
                self.ATYP_IPV4,
                ip_addr.packed,
                dst_port
            ))
        elif isinstance(ip_addr, ipaddress.IPv6Address):
            writer.write(struct.pack(
                '!4B16sH', 
                self.VERSION, 
                self.CMD_CONNECT if scheme == Scheme.TCP else self.CMD_UDP_ASSOCIATE,
                0, 
                self.ATYP_IPV6,
                ip_addr.packed,
                dst_port
            ))
        else:
            raise ValueError('Invalid remote address "%s"' % (s_addr(remote_addr), ))

        await writer.drain()
        _, rep, _, atype,  = struct.unpack('!4B', await reader.readexactly(4))

        if rep != self.REP_SUCCESS:
            raise ConnectionError('Failed to connection remote address "%s"' % (s_addr(remote_addr), ))

        if atype == self.ATYP_IPV4:
            bind_addr, bind_port = struct.unpack('!4sH', await reader.readexactly(6))
            bind_addr = str(ipaddress.IPv4Address(bind_addr))
        elif atype == self.ATYP_IPV6:
            bind_addr, bind_port = struct.unpack('!16sH', await reader.readexactly(18))
            bind_addr = str(ipaddress.IPv6Address(bind_addr))
        else:
            raise ConnectionError('Invalid response atype')

        if scheme != Scheme.UDP and (bind_addr != self.host or bind_port != self.port):
            raise ConnectionError('Relay mode does not supported')

        return bind_addr, bind_port

    async def handshake(self, reader, writer, remote_addr):
        try:
            await self._handshake(reader, writer, remote_addr, Scheme.TCP)
        except ConnectionError:
            return False

        return True

    async def make_udp_tunnel(self, reader, writer, remote_addr):
        return self.UDPTunnel(
            await self._handshake(reader, writer, remote_addr, Scheme.UDP)
        )


def parse_proxy(url):
    if not url:
        return None

    parsed_url = urlsplit(url)
    if parsed_url.path != '' and \
        parsed_url.path != '/' or \
        parsed_url.query != '' or \
        parsed_url.fragment != '':
        raise ValueError('Invalid proxy "%s"' % (url, ))

    try:
        ipaddress.ip_address(parsed_url.hostname)
        host = parsed_url.hostname
    except ValueError:
        host = None

    if parsed_url.scheme == 'http':
        return HttpProxy(
            url, 
            parsed_url.hostname, 
            parsed_url.port if parsed_url.port \
                else DEFAULT_HTTP_PROXY_PORT,
            host,
            parsed_url.username,
            parsed_url.password
        )
    elif parsed_url.scheme == 'socks5':
        return Socks5Proxy(
            url, 
            parsed_url.hostname, 
            parsed_url.port if parsed_url.port \
                else DEFAULT_SOCKS5_PROXY_PORT,
            host,
            parsed_url.username,
            parsed_url.password
        )
    else:
        raise ValueError('Invalid proxy scheme "%s" in "%s"' % (parsed_url.scheme, url))
