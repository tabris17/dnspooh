import unittest

class ConfigTest(unittest.TestCase):

    def test_proxy(self):
        from config import Proxy, HttpProxy
        proxy = Proxy('http://localhost')
        self.assertTrue(isinstance(proxy, HttpProxy))