import asyncio, socket, threading, time

from scapy.all import sendp, sniff
from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw

# Encryption Imports
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import bcrypt, scrypt

from main import inputStream

RX_Bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
RX_IP = "127.0.0.1"
RX_PORT = 14550


async def packageHandler(pkt):
    if pkt.haslayer(IP) and pkt[IP].src == "127.0.0.1":
        RX_Bridge.sendto(pkt[Raw].load, (RX_IP, RX_PORT))


# These two functions work to ensure that we capture 99% of incoming packets despite background processing
def inputHandler(pkt):
    inputStream.put(pkt)


def wirelessReceiver():
    sniff(iface='wlan1', prn=inputHandler, filter="udp and host 127.0.0.1")


class Radio:
    dataFrame = RadioTap() / Dot11(addr1="00:00:00:00:00:00",
                                   addr2="00:00:00:00:00:00",
                                   addr3="00:00:00:00:00:00",
                                   type=2,
                                   subtype=8) / Dot11QoS() / LLC() / SNAP() / IP(src='127.0.0.1',
                                                                                 dst='127.0.0.1') / \
                UDP(sport=5000, dport=5001)

    def __init__(self, output_Stream, input_Stream, interface="wlan1"):
        self.interface = interface
        self.outputStream = output_Stream
        self.input = input_Stream
        # Identity variables
        self.ID = None
        self.target = None
        self.channel = '36'
        # Cryptography variables
        # Exchange variables
        self.curve = ec.SECP256R1
        self.ownKey = None
        self.targetKey = None
        self.masterSecret = None
        # ChaCha20 variables
        self.currentSecret = None
        self.eEngine = None
        # Startup the radio listener thread
        listener = threading.Thread(wirelessReceiver())
        listener.start()
        # Upon initiating, attempt to connect to a second radio in order to exchange keys
        # Radios start by default on channel 36
        # Message ID's: 1 is handshake,
        self.handshake()

    def encrypt(self, message):
        """
        Small function used to manage the act of creating a unique encryption item as required by pycryptodome
        :param message: [String] The plaintext we want to encrypt
        :return: [Bytes] The encrypted message
        """
        self.eEngine = ChaCha20_Poly1305.new(key=self.currentSecret, nonce=b'00000000')
        return b''.join(self.eEngine.encrypt_and_digest(message.encode()))
    # potentially think of storing and using the past message MAC as the next nonce for our message
    # the last mac we generated during encryption is the next mac we use to decrypt
    def decrypt(self, message, mac):
        """
        Small function used to manage the act of creating a unique decryption item as required by pycryptodome
        :param message: [bytes] the encrypted message
        :param mac: [bytes] the associated MAC code
        :return: [String or None] returns the plaintext or none if the decryption fails
        """
        self.eEngine = ChaCha20_Poly1305.new(key=self.currentSecret, nonce=b'00000000')
        try:
            return self.eEngine.decrypt_and_verify(message, mac)
        except ValueError or TypeError:
            return None

    async def tx(self):
        # print("Started")
        while True:
            msg = await self.outputStream.read()
            if msg is None:
                await asyncio.sleep(0.01)
            else:
                print(msg)
                data = self.dataFrame / Raw(load=msg)
                await packageHandler(data)
                # sendp(self.dataFrame / Raw(load=msg), iface=self.interface)

    async def rx(self):
        # QGroundControl binds to port 14550 upon start, thus forward all of our received messages to there.
        # This method is used to capture the broadcast from the drone and hand it to the QGC program
        while True:
            sniff(iface=self.interface, prn=packageHandler, store=0, filter="udp and host 127.0.0.1")
        pass

    async def self_RX(self, vehicle):
        # QGC will try to send its messages according to the packet information that we pass it
        # we thus need to capture this information to correctly package and send it via the wireless broadcast
        TX_Bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        TX_Bridge.bind((RX_IP, 52796))
        while True:
            msg = bytearray(280)
            TX_Bridge.recv_into(msg)
            msg = msg.rstrip(b'\x00')
            m = vehicle.decode(msg)
            print(m)
            await asyncio.sleep(0.01)
        pass

    def handshake(self):
        # ID is of size 3 FIXED
        self.ID = "GCS"
        # Step 0, generate keys
        # self.keys = ECC.generate(curve='p256')

        self.ownKey = ec.generate_private_key(self.curve)

        # General message format: MessageType,ID,Contents, [1:3:n]bytes

        # Step 1, broadcast information
        # Initial handshake, broadcast your identity, public key, and channel

        # This can be augmented with signatures linked to the ID, fixed message is encrypted using their private key
        # which we check we can decrypt with their public key
        msg = bytearray()
        msg.extend(('0' + self.ID).encode())
        msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                         format=serialization.PublicFormat.OpenSSH))
        msg.extend(self.channel.encode())
        sendp(self.dataFrame / Raw(load=msg), iface=self.interface)
        # Step 2, listen for either a broadcast or broadcast response
        while True:
            if not self.input.empty():
                pkt = self.input.get()
                msg = pkt[Raw].load
                if self.currentSecret is not None:
                    # if a key is active, try to decrypt the message
                    msg = self.decrypt(msg[0:-16],msg[-16:])

                if msg is None or msg[1:4].decode() == self.ID:
                    # we check if the message did not decrypt or if we captured our own message
                    # if either of these are true, we should ignore the message
                    pass
                else:
                    # Data is valid, process as normal
                    print("Message Type: " + msg[0:1].decode())
                    if msg[0:1].decode() == '0':
                        print("Got broadcast from: " + msg[1:4].decode() + " on channel: " + msg[-2:].decode())
                        self.target = msg[1:4].decode()
                        # Step 3, extract public key
                        self.targetKey = serialization.load_ssh_public_key(msg[4:-2])

                        # Got a broadcast, respond with ID, pubKey
                        msg = bytearray()
                        msg.extend(('1' + self.ID).encode())
                        msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                         format=serialization.PublicFormat.OpenSSH))
                        sendp(self.dataFrame / Raw(load=msg), iface=self.interface)
                        print("Responded with own data....")

                        # Generate initial shared secret
                        sharedSecret = self.ownKey.exchange(ec.ECDH(), self.targetKey)
                        self.masterSecret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                                 info=b'handshake data', ).derive(sharedSecret)

                        # Generate a proper key, using a fixed salt for now, possibility of adding a future change
                        self.currentSecret = scrypt(self.masterSecret, '0', 32, 1024, 8, 1)

                        # Now wait for the target to respond first, goto step 5

                    elif msg[0:1].decode() == '1':
                        print("Got response from " + msg[1:4].decode())
                        self.target = msg[1:4].decode()
                        # Step 4, generate shared secret
                        self.targetKey = serialization.load_ssh_public_key(msg[4:])
                        sharedSecret = self.ownKey.exchange(ec.ECDH(), self.targetKey)
                        self.masterSecret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                                 info=b'handshake data', ).derive(sharedSecret)
                        # Generate a proper key, using a fixed salt for now, possibility of adding a future change
                        self.currentSecret = scrypt(self.masterSecret, '0', 32, 1024, 8, 1)
                        # Now broadcast an encrypted message back to the other device
                        # This message consists of the concatenation of the device ID's and the current channel
                        data = '2' + msg[1:4].decode() + self.ID + '36'
                        sendp(self.dataFrame / Raw(load=self.encrypt(data)), iface=self.interface)
                        print("Sent cipher authentication msg")
                    elif msg[0:1].decode() == '2':
                        # Step 5, verify that the encryption keys are correct
                        print("STEP 2")
                        if msg[1:].decode() == self.ID+self.target+self.channel:
                            print("KEY GOOD")
                        else:
                            print("KEY BAD")
                            # for a bad key scenario, we send back a message of plaintext "XXXXXXX..."
                            # this signals to both parties to clear their obtained data and start again
                            sendp(self.dataFrame / Raw(load="XXXXXXXXXXXXXXXX"), iface=self.interface)
                            time.sleep(0.01)
                            # resend our broadcast to re-initiate the pairing process
                            msg = bytearray()
                            msg.extend(('0' + self.ID).encode())
                            msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                             format=serialization.PublicFormat.OpenSSH))
                            msg.extend(self.channel.encode())
                            sendp(self.dataFrame / Raw(load=msg), iface=self.interface)
                        exit()
