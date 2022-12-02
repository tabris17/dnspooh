

class Middleware:
    def __init__(self, next):
        self.next = next

    def abort(self):
        return self.next.abort()

    async def handle(self, request, **kwarg):
        return await self.next.handle(request, **kwarg)
