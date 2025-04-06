import asyncio
from Crypto.Protocol.KDF import scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from Drone.device import Device



class Drone(Device):
    def __init__(self, device_id, interface, channel, port, own_device):
        super().__init__(device_id, interface, channel, port, own_device)
        self._active = False
        self._gcs = None
        print("Drone")
        if own_device:
            asyncio.create_task(self.manage_incoming_packets())
            asyncio.create_task(self.manage_outgoing_packets())
            asyncio.create_task(self.broadcast())
        print("Setup done")

    def set_send_queue(self, new_queue):
        self._send_queue = new_queue



    async def broadcast(self):
        # format:
        # [0] type
        # [1,2] msg_id
        # [3,4,5] device id
        # [6:] key
        msg_id = 0
        msg = bytearray()
        msg.extend(
            self._own_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )

        while not self._active:
            self._current_secret = None
            self._send_queue.write([msg_id, msg, False])
            await asyncio.sleep(10)

    def handshake_challenge(self, msg):
        # [3,4,5] device ID
        # [6,7] port allocation
        # [8:] key
        device_id = msg[3:6].decode()
        # device_port = msg[6:8]
        device_key = msg[8:]
        # derive key
        target_key = serialization.load_ssh_public_key(device_key)
        shared_secret = self._own_key.exchange(ec.ECDH(), target_key)
        master_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(shared_secret)
        # Generate a proper key, using a fixed salt for now,
        # possibility of adding a future change
        current_secret = scrypt(
            master_secret, "0", 32, 1024, 8, 1
        )
        self._current_secret = current_secret
        print("key set")
        # format:
        # [0] type (2)
        # [1,2] msg_id
        # [3,4,5] device id
        # [6,7,8] gcs id
        # broadcast the challenge message
        msg_id = 2
        msg = bytearray()
        msg.extend(device_id.encode())
        msg.extend(self._id.encode())
        self._send_queue.write([msg_id, msg, True])

    @property
    def active(self):
        return self._active
