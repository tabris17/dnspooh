import io
import sys
import asyncio
import pathlib


__all__ = ('Middleware', 'CacheMiddleware', 'HostsMiddleware', 'BlockMiddleware', 'RulesMiddleware', 'LogMiddleware')


def _middleware_name_to_class_name(name):
    return ''.join(
        [_.capitalize() for _ in name.split('_')]
    ) + 'Middleware'


def create_middleware(name, next, config):
    class_name = _middleware_name_to_class_name(name)
    if class_name not in __all__: return next
    middleware_class = getattr(sys.modules[__name__], class_name)
    if config is None:
        middleware = middleware_class()
    elif isinstance(config, list):
        middleware = middleware_class(*config)
    elif isinstance(config, dict):
        middleware = middleware_class(**config)
    else:
        middleware = middleware_class(config)
    middleware.initialize(next, name)
    return middleware


async def load_config(filename, server, parser):
    if filename.startswith(('http://', 'https://')):
        response = await server.fetch(filename)
        fp = io.StringIO(response.body.decode())
    else:
        fp = pathlib.Path(filename).open('r')
    with fp:
        return await asyncio.to_thread(parser, fp)


class Traceback(list):
    pass


class Middleware:
    @property
    def server(self):
        if hasattr(self, '_server'):
            return self._server
        from ..server import Server
        if isinstance(self.next, Server):
            self._server = self.next
            return self._server
        self._server =  self.next.server
        return self._server

    def get_component(self, name):
        if self.name == name:
            return self
        if not hasattr(self.next, self.get_component.__name__):
            raise ValueError('Middleware %s not found' % (name, ))
        return self.next.get_component(name)

    def initialize(self, next, name):
        self.next = next
        self.name = name

    def abort(self):
        return self.next.abort()

    def abort(self):
        return self.next.abort()

    async def handle(self, request, **kwargs):
        if 'traceback' in kwargs:
            name = self.next.name if isinstance(self.next, __class__) \
                else self.next.__class__.__name__
            kwargs['traceback'].append(name)
        return await self.next.handle(request, **kwargs)

    async def bootstrap(self):
        return await self.next.bootstrap()

    async def restart(self):
        return await self.next.restart()

    async def reload(self):
        return await self.next.reload()


from .cache import CacheMiddleware
from .hosts import HostsMiddleware
from .block import BlockMiddleware
from .rules import RulesMiddleware
from .log import LogMiddleware
