import asyncio
from device import Device

from Crypto.Protocol.KDF import scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class GCS(Device):
    def __init__(self, device_id, interface, channel, port, own_device):
        super().__init__(device_id, interface, channel, port, own_device)
        self.id_map = {}  # {id:[obj]}
        self.port_map = {}  # {port:[obj]}
        asyncio.create_task(self.manage_incoming_packets())
        asyncio.create_task(self.manage_outgoing_packets())

    async def manage_incoming_packets(self):
        while self._running:
            if not self._receive_queue.empty():
                msg = self._receive_queue.get_nowait()
                # need way to check both encrypted and decrypted
                if self._current_secret is not None:
                    dec_msg = self.decrypt(msg[0:-16], msg[-16:])
                    if dec_msg is not None:  # if decrypted properly, make msg the decrypted value, else use plain
                        msg = dec_msg
                # check the message is not our owns
                if msg[3:6].decode() != self._id:
                    print("Got incoming message")
                    print(msg)
                    msg_type = int.from_bytes(msg[0:1], "big")
                    print("Message type:", msg_type)
                    if msg_type == 0 and self._current_secret is None:
                        # new broadcast from a drone
                        print("Got client broadcast")
                        await self.new_client(msg)
                    elif msg_type == 2 and self._current_secret is not None:
                        self.send_ack(msg[1:3])
                        print("Got handshake challenge")
                        # handshake challenge by client, respond with ack
                        self.client_confirm(msg)
                    elif msg_type == 4:
                        # management message
                        if msg[6] == 0:
                            # ACK message
                            # ACK format:
                            # [0] type (4)
                            # [1,2] message id
                            # [3,4,5] device id
                            # [6] management frame type (0)
                            # [7,8] ACK message ID
                            print("Got ACK for:", int.from_bytes(msg[7:9], "big"))
                            self._radio.clear_timer(int.from_bytes(msg[7:9], "big"))
                        else:
                            self.send_ack(msg[1:3])

            else:
                await asyncio.sleep(0.01)

    async def new_client(self, msg):
        device_id = msg[3:6].decode()
        device_key = serialization.load_ssh_public_key(msg[6:])
        device_port = 5000
        print("Detected drone with ID: " + device_id)
        # derive key details
        target_key = device_key
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
        print("Shared, master, current secret:")
        print(shared_secret)
        print(master_secret)
        print(current_secret)

        # Got a broadcast, respond with ID, pubKey, port
        # format:
        # [0] type
        # [1,2] msg_id
        # [3,4,5] device id
        # [6,7] port
        # [8:] key
        msg = bytearray()
        msg.extend(device_port.to_bytes(2, "big"))
        msg.extend(
            self._own_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )
        #self._send_queue.write([1, msg, True])
        self.send(1,msg,True) # manually send before encryption value is set
        print("Responded with own data....")

        self._current_secret = current_secret

    def client_confirm(self, msg):
        # confirm a client device by accepting their handshake challenge and issuing the correct response
        device_id = msg[3:6].decode()
        msg_id = 3
        response = bytearray()
        response.extend(device_id.encode())
        response.extend(self._id.encode())
        self.send(msg_id, response, True)
        print("Client device confirmed")
