import logging

from . import Middleware


logger = logging.getLogger(__name__)


class RulesMiddleware(Middleware):
    def __init__(self, next, *rules):
        super().__init__(next)
        self.rules = rules

    async def handle(self, request, **kwargs):
        return await super().handle(request, **kwargs)
        
