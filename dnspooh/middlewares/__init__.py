import sys

from .cache import CacheMiddleware
from .hosts import HostsMiddleware


__all__ = ('Middleware', 'CacheMiddleware', 'HostsMiddleware')


def create_middleware(name, next, config):
    class_name = ''.join([_.capitalize() for _ in name.split('_')]) + 'Middleware'
    if class_name not in __all__: return next
    middleware_class = getattr(sys.modules[__name__], class_name)
    if config is None:
        return middleware_class(next)
    elif isinstance(config, list):
        return middleware_class(next, *config)
    elif isinstance(config, dict):
        return middleware_class(next, **config)
    return middleware_class(next, config)


class Middleware:
    @property
    def server(self):
        if hasattr(self, '_server'):
            return self._server
        from server import Server
        if isinstance(self.next, Server):
            self._server = self.next
            return self._server
        self._server =  self.next.server
        return self._server

    def __init__(self, next):
        self.next = next

    def abort(self):
        return self.next.abort()

    def abort(self):
        return self.next.abort()

    async def handle(self, request, *args, **kwarg):
        return await self.next.handle(request, *args, **kwarg)

    async def bootstrap(self):
        return await self.next.bootstrap()

    async def restart(self):
        return await self.next.restart()

    async def reload(self):
        return await self.next.reload()
