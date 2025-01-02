import asyncio
from enum import Enum
from multiprocessing import Queue
from Communications.message_store import MessageStore
from Communications.radio import Radio


class DroneType(Enum):
    GCS = 0,
    UAV = 1,


class Device:
    def __init__(self, device_type, device_id, interface, channel, port):
        self.drone_type = device_type
        self.id = device_id
        self.port = port

        self.encryption_engine = None
        self.shared_secret = None
        self.send_queue = MessageStore()
        self.receive_queue = Queue()

        self.radio = Radio(self.send_queue,
                           self.receive_queue,
                           self.id,
                           channel,
                           self.port,
                           self.port,
                           interface,)

    def get_queues(self):
        return [self.send_queue, self.receive_queue]

    def stop(self):
        self.radio.end()


class GCS(Device):
    def __init__(self, device_type, device_id, interface, channel, port):
        super().__init__(device_type, device_id, interface, channel, port)
        while True:
            if not self.receive_queue.empty():
                msg = self.receive_queue.get(False)


class Drone(Device):
    def __init__(self, device_type, device_id, interface, channel, port):
        super().__init__(device_type, device_id, interface, channel, port)
