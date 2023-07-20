import queue
class messageStore:

    def __init__(self):
        self.store = queue.Queue()

    def write(self, data):
        self.store.put(data)

    async def read(self):
        return self.store.get()

    async def getSize(self):
        return self.store.qsize()
