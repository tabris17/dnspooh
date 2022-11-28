import asyncio
import logging

from cachetools import TTLCache
from dnslib import QTYPE


logger = logging.getLogger(__name__)


class Middleware:
    def __init__(self, next):
        self.next = next

    def abort(self):
        return self.next.abort()

    async def handle(self, request, **kwarg):
        return await self.next.handle(request, **kwarg)


class CacheMiddleware(Middleware):
    def __init__(self, next, max_size, ttl):
        super().__init__(next)
        self.cache = TTLCache(maxsize=max_size, ttl=ttl)

    async def handle(self, request, upstreams=None):
        if request.header.q > 1:
            return await super().handle(request)

        cache_key = '%s;%s' % (request.q.qname, QTYPE[request.q.qtype])
        if cache_key in self.cache:
            logger.debug('Cache hit "%s"', cache_key)
            return self.cache[cache_key]

        logger.debug('Cache miss "%s"', cache_key)
        response = await super().handle(request)
        if response is not None:
            self.cache[cache_key] = response
        return response


class RuleMiddleware(Middleware):
    pass
