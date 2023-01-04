import logging

from . import Middleware


logger = logging.getLogger(__name__)


class RulesMiddleware(Middleware):
    async def handle(self, request, **kwargs):
        return await super().handle(request, **kwargs)
        
