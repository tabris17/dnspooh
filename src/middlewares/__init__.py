import sys

from .middleware import Middleware
from .cache import CacheMiddleware


__all__ = ('Middleware', 'CacheMiddleware')


def get_class(name):
    class_name = ''.join([_.capitalize() for _ in name.split('_')]) + 'Middleware'
    if class_name not in __all__: return
    return getattr(sys.modules[__name__], class_name)
