
class NotFoundException(Exception):
    pass

class InvalidRequest(Exception):
    pass

class UnauthorizedClient(Exception):
    pass

class AccessDenied(Exception):
    pass

class UnsupportedResponseType(Exception):
    pass

class InvalidScope(Exception):
    pass

class ServerError(Exception):
    pass

class TemporarilyUnavailable(Exception):
    pass
