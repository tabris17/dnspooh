
class EmptyValueError(ValueError): pass

class UnexpectedValueError(ValueError): pass

class InvalidConfig(Exception): pass

class HttpException(Exception): pass

class HttpHeaderTooLarge(HttpException): CODE = 431

class HttpPayloadTooLarge(HttpException): CODE = 413

class HttpNotFound(HttpException): CODE = 404

class HttpMethodNotAllowed(HttpException): CODE = 405

class NetworkError(RuntimeError): pass
