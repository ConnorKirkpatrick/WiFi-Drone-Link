from multiprocessing import Queue


class MessageStore:

    def __init__(self):
        self.store = Queue()

    def write(self, data):
        self.store.put(data)

    def read(self):
        if self.get_size() < 1:
            return None
        return self.store.get_nowait()

    def get_size(self):
        return self.store.qsize()
