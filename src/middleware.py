import asyncio
import logging

from cachetools import TTLCache
from dnslib import QTYPE


class Middleware:
    def __init__(self, next):
        self.next = next

    def abort(self):
        return self.next.abort()

    async def handle(self, request, upstreams=None):
        return await self.next.handle(request, upstreams)


class CacheMiddleware(Middleware):
    def __init__(self, next, max_size, ttl):
        super().__init__(next)
        self.cache = TTLCache(maxsize=max_size, ttl=ttl)

    async def handle(self, request, upstreams=None):
        if request.header.q > 1:
            return await super().handle(request)

        cache_key = '{0};{1}'.format(request.q.qname, QTYPE[request.q.qtype])
        if cache_key in self.cache:
            logging.debug('Cache hit "{0}"'.format(cache_key))
            return self.cache[cache_key]

        logging.debug('Cache miss "{0}"'.format(cache_key))
        response = await super().handle(request)
        if response is not None:
            self.cache[cache_key] = response
        return response


class RuleMiddleware(Middleware):
    pass
