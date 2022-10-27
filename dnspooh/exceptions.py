
class EmptyValueError(ValueError): pass

class UnexpectedValueError(ValueError): pass

class InvalidConfig(Exception): pass

class HttpException(Exception): pass

class HttpHeaderTooLarge(HttpException): pass

class HttpPayloadTooLarge(HttpException): pass

class HttpNotFound(HttpException): pass

class HttpMethodNotAllowed(HttpException): pass

class NetworkError(RuntimeError): pass
