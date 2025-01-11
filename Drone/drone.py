import asyncio
import secrets

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt, HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from multiprocessing import Queue

from Communications.message_store import MessageStore
from Communications.radio import Radio


class Device:
    def __init__(self, device_id, interface, channel, port, own_device=False):
        self._id = device_id
        self._port = port
        self._active = False
        self._message_id = 0
        self._encryption_engine = None
        # Step 0, generate keys
        self._own_key = ec.generate_private_key(ec.SECP256R1())
        self._shared_secret = None
        self._master_secret = None
        self._current_secret = None
        self._send_queue = MessageStore()
        self._receive_queue = Queue()
        self._running = True
        if own_device:
            self._radio = Radio(self._send_queue,
                                self._receive_queue,
                                self._id,
                                channel,
                                self._port,
                                self._port,
                                interface, )
        else:
            self._radio = None

    def get_queues(self):
        return [self._send_queue, self._receive_queue]

    def set_own_key(self, key):
        self._own_key = key

    def set_shared_secret(self, secret, salt=secrets.randbelow(4_294_967_295)):
        self._shared_secret = secret
        self._master_secret = HKDF(
            master=self._shared_secret,
            key_len=32,
            hashmod=SHA256,
            salt=salt.to_bytes(32, "big"),
            context=b"master key",
        )

        # Generate a proper key, using a fixed salt for now,
        # possibility of adding a future change
        self._current_secret = scrypt(
            str(self._master_secret), "0", 32, N=1024, r=8, p=1
        )

    def encrypt(self, message):
        """
        Small function used to manage the act of creating a unique encryption item as required by pycryptodome
        :param message: [String] The plaintext we want to encrypt
        :return: [Bytes] The encrypted message
        """
        self._encryption_engine = ChaCha20_Poly1305.new(
            key=self._current_secret, nonce=b"00000000"
        )
        return b"".join(self._encryption_engine.encrypt_and_digest(message))

    # potentially think of storing and using the past message MAC as the next nonce for our message
    # the last mac we generated during encryption is the next mac we use to
    # decrypt
    def decrypt(self, message, mac):
        """
        Small function used to manage the act of creating a unique decryption item as required by pycryptodome
        :param message: [bytes] the encrypted message
        :param mac: [bytes] the associated MAC code
        :return: [String or None] returns the plaintext or none if the decryption fails
        """
        self._encryption_engine = ChaCha20_Poly1305.new(
            key=self._current_secret, nonce=b"00000000"
        )
        try:
            return self._encryption_engine.decrypt_and_verify(message, mac)
        except (ValueError, TypeError):
            return None

    def send(self, message_type, message_contents, need_ack=True):
        """
        This method manages sending data via SCAPY in the correct way.
        Serialisation:
            [0] : The first byte is always the packet type, this can be 0-4, representing handshake packets 0-2, or
            mavlink (3), or management (4) frames
            [1,2] : The second and third bytes are the ID values for the packet, allowing each to be uniquely identified
            [3,4,5]: This contains the ID of the sending platform
            [6:] : bytes 6 onwards is the main content of the packet
        for each packet sent, we can select if it needs an acknowledgment message. If this is true, as it is by default,
        the method will create a new asynchronous task that will trigger the re-send method with the same data after a
        designated time. If an ACK is received before this time, the object can be fetched from the self.timers
        dictionary and canceled

        :param message_type: [Int] Data identifying the packet type
        :param message_contents: [ByteArray] The contents of the packet
        :param need_ack: [Bool]: A flag that will determine if the system will need an ACK or not to confirm receipt
        :return:
        """

        encoded_msg = bytearray()
        encoded_msg.extend(message_type.to_bytes(1, "big"))  # [0]

        # 2 byte value, ID's from 0-65536
        encoded_msg.extend(self._message_id.to_bytes(2, "big"))  # [1,2]
        encoded_msg.extend(self._id.encode())  # [3,4,5]
        encoded_msg.extend(message_contents)  # [6:]

        print("Got new outgoing packet:")
        print(encoded_msg)

        # manage encryption
        if self._current_secret is not None:
            encoded_msg = self.encrypt(encoded_msg)
        self._radio.send(encoded_msg, need_ack)

    def send_ack(self, message_id):
        print("sending ack for id ")
        print(message_id)
        msg = bytearray()
        code = 4
        msg.extend(code.to_bytes(1, "big"))
        msg.extend(message_id)
        self.send(4, msg, False)

    def stop(self):
        self._radio.end()


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
                msg = self._receive_queue.get(False)
                # need way to check both encrypted and decrypted

                if self._current_secret is not None:
                    dec_msg = self.decrypt(msg[0:-16], msg[-16:])
                    if dec_msg is not None:  # if decrypted properly, make msg the decrypted value
                        msg = dec_msg
                        # this means that if we receive data such as ACK after
                        # keys are set, we can still process them
                if msg[3:6].decode() == self._id:
                    return
                print("New incoming message")
                print(msg)
                msg_type = int.from_bytes(msg[0:1], "big")
                print("Message type:", msg_type)
                if msg_type == 0 and self._current_secret is None:
                    # new broadcast from a drone
                    print("Creating new client")
                    await self.new_client(msg)
                elif msg_type == 2 and self._current_secret is not None:
                    self.send_ack(msg[1:3])
                    print("Got handshake challenge")
                    # handshake challenge by client, respond with ack
                    pass
                elif msg_type == 4:
                    # management message
                    if msg[3] == 0:
                        # Got ACK
                        print("Got ACK for:", int.from_bytes(msg[4:], "big"))
                        # key = int.from_bytes(msg[4:], "big")
                        # try:
                        #     timer = self.timers.pop(key)
                        #     while not timer.cancel():
                        #         timer = self.timers.pop(key)
                        #         await asyncio.sleep(0.0001)
                        #     print("Terminated timer successfully")
                        # except KeyError:
                        #     pass
                    else:
                        self.send_ack(msg[1:3])

            else:
                await asyncio.sleep(0.01)

    async def manage_outgoing_packets(self):
        while self._running:
            if not self._send_queue.empty():
                _type, _contents, _ack = self._send_queue.read()
                self.send(_type, _contents, _ack)
            else:
                await asyncio.sleep(0.01)

    async def new_client(self, msg):
        _id = msg[3:6].decode()
        _target_key = serialization.load_ssh_public_key(msg[6:])
        _port = 5005
        _drone = Drone(_id, "", "", _port, False)
        self.id_map[_id] = _drone
        self.port_map[_port] = _drone
        _drone.set_send_queue(self._send_queue)
        print("Detected drone with ID: " + _id)
        # Got a broadcast, respond with ID, pubKey, port
        # format:
        # [0] type
        # [1,2] msg_id
        # [3,4,5] device id
        # [6,7] port
        # [8:] key
        msg = bytearray()
        msg.extend(_port.to_bytes(2, "big"))
        msg.extend(
            self._own_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )
        self._send_queue.write([1, msg, True])
        print("Responded with own data....")

        # generate secret with the clients key
        _drone.set_own_key(_target_key)
        _drone.set_shared_secret(self._own_key.exchange(ec.ECDH(), _target_key))

        await asyncio.sleep(10)
        if not _drone.active:
            del self.id_map[_id]
            del self.port_map[_port]


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

    def set_send_queue(self, new_queue):
        self._send_queue = new_queue

    async def manage_incoming_packets(self):
        while self._running:
            if not self._receive_queue.empty():
                msg = self._receive_queue.get(False)
                # need way to check both encrypted and decrypted

                if self._current_secret is not None:
                    dec_msg = self.decrypt(msg[0:-16], msg[-16:])
                    if dec_msg is not None:  # if decrypted properly, make msg the decrypted value
                        msg = dec_msg
                        # this means that if we receive data such as ACK after
                        # keys are set, we can still process them
                # check if message is from ourselves
                if msg[3:6].decode() == self._id:
                    return
                print("New incoming message")
                print(msg)
                msg_type = int.from_bytes(msg[0:1], "big")
                print("Message type:", msg_type)
                if msg_type == 1 and self._current_secret is None:
                    # Broadcast response
                    print(msg[1:3])
                    self.send_ack(msg[1:3])
                    print("got broadcast response")
                    self.handshake_challenge(msg)
                elif msg_type == 3 and self._current_secret is not None:
                    self.send_ack(msg[1:3])
                    print("Got handshake challenge response")
                    # handshake challenge by client, respond with ack
                    pass
                elif msg_type == 4:
                    # management message
                    if msg[3] == 0:
                        # Got ACK
                        print("Got ACK for:", int.from_bytes(msg[4:], "big"))
                        # key = int.from_bytes(msg[4:], "big")
                        # try:
                        #     timer = self.timers.pop(key)
                        #     while not timer.cancel():
                        #         timer = self.timers.pop(key)
                        #         await asyncio.sleep(0.0001)
                        #     print("Terminated timer successfully")
                        # except KeyError:
                        #     pass
                    else:
                        self.send_ack(msg[1:3])

            else:
                await asyncio.sleep(0.01)

    async def manage_outgoing_packets(self):
        while self._running:
            if not self._send_queue.empty():
                _type, _contents, _ack = self._send_queue.read()
                self.send(_type, _contents, _ack)
            else:
                await asyncio.sleep(0.01)

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
            self._send_queue.write([0, msg, False])
            await asyncio.sleep(10)

    def handshake_challenge(self, msg):
        print(msg)
        _id = msg[3:6].decode()
        _port = msg[6:8]
        _key = msg[8:]
        self._gcs = GCS(_id, "", "", 5002, False)
        # generate secret with the clients key
        _target_key = serialization.load_ssh_public_key(_key)
        self._gcs.set_own_key(_target_key)
        self._gcs.set_shared_secret(self._own_key.exchange(ec.ECDH(), _target_key))

        # format:
        # [0] type
        # [1,2] msg_id
        # [3,4,5] device id
        # [6,7,8] gcs id
        msg = bytearray()
        msg.extend(self._gcs._id.encode())
        self._send_queue.write([2, msg, False])
        print("Responded with own data....")

    @property
    def active(self):
        return self._active
