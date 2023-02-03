import logging

from cachetools import TTLCache
from dnslib import QTYPE

from . import Middleware


logger = logging.getLogger(__name__)


class CacheMiddleware(Middleware):
    def __init__(self, max_size, ttl):
        self.cache = TTLCache(maxsize=max_size, ttl=ttl)

    async def handle(self, request, **kwargs):
        cache_key = '%s;%s' % (request.q.qname, QTYPE[request.q.qtype])
        if cache_key in self.cache:
            logger.debug('Cache hit "%s"', cache_key)
            response = self.cache[cache_key]
            response.header.id = request.header.id
            return response

        logger.debug('Cache miss "%s"', cache_key)
        response = await super().handle(request, **kwargs)
        if response is not None:
            self.cache[cache_key] = response
        return response
