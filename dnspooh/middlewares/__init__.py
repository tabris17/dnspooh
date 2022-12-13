import sys

from .middleware import Middleware
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
