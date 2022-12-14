from server import Server


class Middleware:
    @property
    def server(self):
        if self._server:
            return self._server
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

    async def handle(self, request, **kwarg):
        return await self.next.handle(request, **kwarg)

    async def bootstrap(self):
        return await self.next.bootstrap()

    async def restart(self):
        return await self.next.restart()

    async def reload(self):
        return await self.next.reload()
