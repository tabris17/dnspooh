
class EmptyValueError(ValueError): pass

class UnexpectedValueError(ValueError): pass

class InvalidConfig(Exception): pass

class HttpException(Exception): pass

class HttpRequestException(HttpException): pass

class HttpResponseException(HttpException): pass
