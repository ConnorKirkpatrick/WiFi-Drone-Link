import queue
class messageStore:

    def __init__(self):
        self.store = queue.Queue()

    def write(self, data):
        self.store.put(data)

    async def read(self):
        if await self.getSize() < 1:
            return None
        else:
            return self.store.get_nowait()

    async def getSize(self):
        return self.store.qsize()
