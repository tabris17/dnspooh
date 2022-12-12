import sys

from .middleware import Middleware
from .cache import CacheMiddleware


__all__ = ('Middleware', 'CacheMiddleware')


def create_middleware(name, next, kwargs):
    class_name = ''.join([_.capitalize() for _ in name.split('_')]) + 'Middleware'
    if class_name not in __all__: return next
    middleware_class = getattr(sys.modules[__name__], class_name)
    return middleware_class(next, **kwargs) if kwargs else \
        middleware_class(next)
