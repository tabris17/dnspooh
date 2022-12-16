import logging

from . import Middleware


logger = logging.getLogger(__name__)


class RuleMiddleware(Middleware):
    async def handle(self, request, upstreams=None):
        if request.header.q > 1:
            return await super().handle(request, upstreams)
        
