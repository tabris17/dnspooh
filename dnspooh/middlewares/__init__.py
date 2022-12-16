import sys


__all__ = ('Middleware', 'ReassembleMiddleware', 'FragmentMiddleware', 
           'CacheMiddleware', 'HostsMiddleware')


def _middleware_name_to_class_name(name):
    return ''.join(
        [_.capitalize() for _ in name.split('_')]
    ) + 'Middleware'


def create_middleware(name, next, config):
    class_name = _middleware_name_to_class_name(name)
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

    def get_component(self, name):
        class_name = _middleware_name_to_class_name(name)
        if __class__.__name__ == class_name:
            return self
        if not hasattr(self.next, self.get_component.__name__):
            raise ValueError('Middleware %s not found' % (name, ))
        return self.next.get_component(name)

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


from .cache import CacheMiddleware
from .hosts import HostsMiddleware


class ReassembleMiddleware(Middleware):
    def __init__(self, next):
        super().__init__(next)
        self.started = False

    async def __aenter__(self):
        print("in aenter")

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.handle()

    async def handle(self, request, *args, **kwarg):
        return await self.next.handle(request, *args, **kwarg)


class FragmentMiddleware(Middleware):
    def __init__(self, next):
        super().__init__(next)
        self.reassemble = self.get_component('reassemble')

    async def handle(self, request, *args, **kwarg):
        async with self.reassemble:
            pass
