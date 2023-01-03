import logging

from . import Middleware


logger = logging.getLogger(__name__)


class RuleMiddleware(Middleware):
    async def handle(self, request, upstreams=None):
        pass
        
