import unittest
import socket

class SendTest(unittest.TestCase):

    def test_echo(self):
        data = 'ping'
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(data.encode(), ('10.21.132.11', 53))
        self.assertEqual(udp.recv(1024).decode(), 'ping')
        udp.close()
