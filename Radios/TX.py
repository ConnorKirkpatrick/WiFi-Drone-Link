import asyncio, socket

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

RX_Bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
RX_IP = "127.0.0.1"
RX_PORT = 14550


async def packageHandler(pkt):
    if pkt.haslayer(IP) and pkt[IP].src == "127.0.0.1":
        RX_Bridge.sendto(pkt[Raw].load, (RX_IP, RX_PORT))


class Radio:
    dataFrame = RadioTap() / Dot11(addr1="00:00:00:00:00:00",
                                   addr2="00:00:00:00:00:00",
                                   addr3="00:00:00:00:00:00",
                                   type=2,
                                   subtype=8) / Dot11QoS() / LLC() / SNAP() / IP(src='127.0.0.1',
                                                                                 dst='127.0.0.1') / \
                UDP(sport=5000, dport=5001)

    def __init__(self, data_stream, interface="wlan1"):
        self.interface = interface
        self.data = data_stream

        self.curve = ec.SECP256R1
        self.keys = None
        self.targetKey = None
        # Upon initiating, attempt to connect to a second radio in order to exchange keys
        # Radios start by default on channel 36
        # Message ID's: 1 is handshake,
        self.handshake()

    async def tx(self):
        # print("Started")
        while True:
            msg = await self.data.read()
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
        ID = "GCS"
        # Step 0, generate keys
        # self.keys = ECC.generate(curve='p256')

        self.keys = ec.generate_private_key(self.curve)
        print(self.keys.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                  format=serialization.PublicFormat.OpenSSH))
        # Step 1, broadcast information
        # Initial handshake, broadcast your identity, public key, and channel

        # This can be augmented with signatures linked to the ID, fixed message is encrypted using their private key
        # which we check we can decrypt with their public key
        msg = bytearray()
        msg.extend(('0' + ID).encode())
        msg.extend(self.keys.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                       format=serialization.PublicFormat.OpenSSH))
        msg.extend("36".encode())
        sendp(self.dataFrame / Raw(load=msg), iface=self.interface)

        # Step 2, listen for either a broadcast or broadcast response
        while True:
            pkt = sniff(iface=self.interface, filter="udp and host 127.0.0.1", count=1)[0]
            msg = pkt[Raw].load
            print(msg)
            print("Type: " + msg[0:1].decode())

            if msg[0:1].decode() == '0':
                print("ID: " + msg[1:4].decode())
                print("Chan: " + msg[-2:].decode())
                # Step 3, extract public key
                print(msg[4:-2])
                self.targetKey = serialization.load_ssh_public_key(msg[4:-2])

                # Got a broadcast, respond with ID, pubKey
                msg = bytearray()
                msg.extend(('1' + ID).encode())
                msg.extend(self.keys.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                               format=serialization.PublicFormat.OpenSSH))
                sendp(self.dataFrame / Raw(load=msg), iface=self.interface)

                # Generate initial shared secret
                sharedSecret = self.keys.exchange(ec.ECDH(), self.targetKey)
                derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', ).derive(
                    sharedSecret)
                print(derived_key)
                # Generate a proper key
                keySecret = bcrypt(derived_key, 15,b'0000000000000000')
                x = scrypt(derived_key.decode(), '0', 32, 1024, 8, 1)
                print(keySecret)
                # Now wait for the target to respond first

            elif msg[0:1].decode() == '1':
                # Step 4, generate shared secret
                self.targetKey = serialization.load_ssh_public_key(msg[4:])
                sharedSecret = self.keys.exchange(ec.ECDH(), self.targetKey)
                derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', ).derive(
                    sharedSecret)
                print(derived_key)
                keySecret = bcrypt(derived_key, 15, b'0000000000000000')
                x = scrypt(derived_key.decode(), '0', 32, 1024, 8, 1)
                print(keySecret)

        # Initial handshake, broadcast your identity, public key, and channel
        # upon receiving a handshake broadcast, encrypt a phrase using the targets public key, respond with own ID, own
        # pub-Key, and the encrypted message
        # Target should respond with your message encrypted with your public key, and then a new phrase encrypted with
        # your key again
        # Final response is made using the targets public key and the combination of both messages
        # After the final message, a shared secret is generated and used to encrypt the contents of all further messages
