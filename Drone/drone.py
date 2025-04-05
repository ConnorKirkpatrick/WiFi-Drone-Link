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

    async def manage_incoming_packets(self):
        while self._running:
            if not self._receive_queue.empty():
                msg = self._receive_queue.get_nowait()
                # need way to check both encrypted and decrypted
                if self._current_secret is not None:
                    dec_msg = self.decrypt(msg[0:-16], msg[-16:])
                    if dec_msg is not None:  # if decrypted properly, make msg the decrypted value, else use plain
                        msg = dec_msg
                ## check the message is not our owns
                if msg[3:6].decode() != self._id:
                    print("Got incoming message")
                    print(msg)
                    msg_type = int.from_bytes(msg[0:1], "big")
                    print("Message type:", msg_type)
                    if msg_type == 1 and self._current_secret is None:
                        # Broadcast response
                        self.send_ack(msg[1:3])
                        print("got broadcast response")
                        self.handshake_challenge(msg)
                    elif msg_type == 3 and self._current_secret is not None:
                        self.send_ack(msg[1:3])
                        print("Got handshake challenge response")
                        print("GCS Connection confirmed")
                        self._active = True
                        # handshake challenge by client, respond with ack
                    elif msg_type == 4:
                        # management message
                        if msg[6] == 0:
                            # Got ACK
                            print("Got ACK for:", int.from_bytes(msg[7:9], "big"))
                            self._radio.clear_timer(int.from_bytes(msg[7:9], "big"))
                        else:
                            self.send_ack(msg[1:3])
                    else:
                        print("Unknown message obtained")
                        print(msg)
            else:
                await asyncio.sleep(0.001)

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
