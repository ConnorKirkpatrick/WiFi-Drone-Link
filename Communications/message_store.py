from multiprocessing import Queue


class MessageStore:

    def __init__(self):
        self.store = Queue()

    def write(self, data):
        self.store.put(data)

    def read(self):
        if self.store.empty():
            return None
        return self.store.get_nowait()

    def empty(self):
        return self.store.empty()
