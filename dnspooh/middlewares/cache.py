import logging

from cachetools import TTLCache
from dnslib import QTYPE

from . import Middleware


logger = logging.getLogger(__name__)


class CacheMiddleware(Middleware):
    def __init__(self, next, max_size, ttl):
        super().__init__(next)
        self.cache = TTLCache(maxsize=max_size, ttl=ttl)

    async def handle(self, request, upstreams=None):
        if request.header.q > 1:
            return await super().handle(request, upstreams)

        cache_key = '%s;%s' % (request.q.qname, QTYPE[request.q.qtype])
        if cache_key in self.cache:
            logger.debug('Cache hit "%s"', cache_key)
            response = self.cache[cache_key]
            response.header.id = request.header.id
            return response

        logger.debug('Cache miss "%s"', cache_key)
        response = await super().handle(request)
        if response is not None:
            self.cache[cache_key] = response
        return response
