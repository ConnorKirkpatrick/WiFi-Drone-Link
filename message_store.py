import queue


class MessageStore:

    def __init__(self):
        self.store = queue.Queue()

    def write(self, data):
        self.store.put(data)

    async def read(self):
        if await self.get_size() < 1:
            return None
        return self.store.get_nowait()

    async def get_size(self):
        return self.store.qsize()
