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

    def stop(self):
        self._radio.end()


class GCS(Device):
    def __init__(self, device_id, interface, channel, port, own_device):
        super().__init__(device_id, interface, channel, port, own_device)
        self.id_map = {}  # {id:[obj]}
        self.port_map = {}  # {port:[obj]}
        asyncio.create_task(self.manage_incoming_packets())

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

    async def manage_incoming_packets(self):
        while self._running:
            if not self._receive_queue.empty():
                msg = self._receive_queue.get(False)
                # need way to check both encrypted and decrypted
                self._radio.ack(msg[1:3])
                print(msg)
                if self._current_secret is not None:
                    dec_msg = self.decrypt(msg[0:-16], msg[-16:])
                    if dec_msg is not None:  # if decrypted properly, make msg the decrypted value
                        msg = dec_msg
                        # this means that if we receive data such as ACK after
                        # keys are set, we can still process them
                msg_type = int.from_bytes(msg[0:1], "big")
                print("Message type:", msg_type)
                if msg_type == 0 and self._current_secret is None:
                    # new broadcast from a drone
                    print("Creating new client")
                    self.new_client(msg)
                elif msg_type == 3 and self._current_secret is not None:
                    print("Got handshake challenge")
                    # handshake challenge by client, respond with ack
                    pass
                elif msg_type == 4:
                    # management message
                    if msg[3] == 0:
                        # Got ACK
                        print("Got ACK for:",int.from_bytes(msg[4:], "big"))
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
                        self.ack(msg[1:3])

            else:
                await asyncio.sleep(0.01)

    async def manage_outgoing_packets(self):
        while self._running:
            if not self._receive_queue.empty():
                _type, _contents, _ack = self._receive_queue.get(False)
                self._radio.send(_type, _contents, _ack)
            else:
                await asyncio.sleep(0.01)

    def new_client(self, msg):
        _id = msg[4:7].decode()
        _target_key = serialization.load_ssh_public_key(msg[8:])
        _port = 5005
        _drone = Drone(_id, "", "", _port, False)
        self.id_map[_id] = _drone
        self.port_map[_port] = _drone
        _drone.set_send_queue(self._send_queue)
        print("Detected drone with ID: " + _id)
        # Got a broadcast, respond with ID, pubKey
        msg = bytearray()
        msg.extend(self._id.encode())
        msg.extend(_port.to_bytes(2, "big"))
        msg.extend(
            self._own_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )
        # await self.send(1, msg)
        print("Responded with own data....")

        # generate secret with the clients key
        _drone.set_own_key(_target_key)
        _drone.set_shared_secret(self._own_key.exchange(ec.ECDH(), _target_key))


class Drone(Device):
    def __init__(self, device_id, interface, channel, port, own_device):
        super().__init__(device_id, interface, channel, port, own_device)
        print("Drone")

    def set_send_queue(self, new_queue):
        self._send_queue = new_queue

    def get_new_secret(self, salt=secrets.randbits(32)):
        self._current_secret = scrypt(
            self._master_secret, str(salt), 32, N=1024, r=8, p=1
        )
