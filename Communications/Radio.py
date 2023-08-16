import asyncio, socket, threading, time
from concurrent.futures import ThreadPoolExecutor

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


# from main import inputStream


class Radio:
    def inputHandler(self, pkt):
        # Possibly add address filtering at this layer
        self.input.put(pkt)

    def wirelessReceiver(self):
        sniff(iface='wlan1', prn=self.inputHandler, filter="udp and host 127.0.0.1 and dst port " + str(self.recPort))

    timerPool = ThreadPoolExecutor(10)  # create a threadpool of 10 threads

    def __init__(self, vehicle, output_Stream, input_Stream, ID, channel, recPort, destPort, interface="wlan1"):
        self.vehicle = vehicle
        self.interface = interface
        self.outputStream = output_Stream
        self.input = input_Stream
        self.QGC_Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.QGC_Addr = ("127.0.0.1", 14550)
        self.recPort = int(recPort)
        self.destPort = int(destPort)
        self.dataFrame = RadioTap() / Dot11(addr1="00:00:00:00:00:00",
                                            addr2="00:00:00:00:00:00",
                                            addr3="00:00:00:00:00:00",
                                            type=2,
                                            subtype=8) / Dot11QoS() / LLC() / SNAP() / IP(src='127.0.0.1',
                                                                                          dst='127.0.0.1') / \
                         UDP(sport=self.recPort, dport=self.destPort)

        # Identity variables
        self.ID = ID
        self.target = None
        self.channel = int(channel)
        # Management stores
        self.reserve = {}
        self.timers = {}
        self.messageID = 0
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
        listener = threading.Thread(target=self.wirelessReceiver)
        listener.start()
        # Upon initiating, attempt to connect to a second radio in order to exchange keys
        # Communications start by default on channel 36
        # Message ID's: 1 is handshake,
        self.handshake()

    def encrypt(self, message):
        """
        Small function used to manage the act of creating a unique encryption item as required by pycryptodome
        :param message: [String] The plaintext we want to encrypt
        :return: [Bytes] The encrypted message
        """
        self.eEngine = ChaCha20_Poly1305.new(key=self.currentSecret, nonce=b'00000000')
        return b''.join(self.eEngine.encrypt_and_digest(message))

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
        """
        The Transmission method is used by the drone mainly. This will take the packets sent via the vehicle object
        and then send them via the wireless interface
        :return:
        """
        # print("Started")
        while True:
            msg = await self.outputStream.read()
            if msg is None:
                await asyncio.sleep(0.01)
            else:
                print(msg)
                data = self.dataFrame / Raw(load=msg)
                # await packageHandler(data)
                # TODO: Wrap this data correctly with management IDs
                # sendp(self.dataFrame / Raw(load=msg), iface=self.interface)

                """ 
                If the packet is type 4 (mavlink) we should store it in the reserve under the mavlink ID
                we should also create and store a time in the retransmission store for this message
                If the timer triggers, it pulls the message from the linked store and re-transmits it
                """

    async def rx(self):
        """
        The main Receiver for the application will check the type of data received and then handle it accordingly
        The only 2 data types we should receive during main runtime is types 3 and 4. These are either standard mavlink
        messages, or configuration packages
        Mavlink packages are simply stripped of our ID information and then passed to the QGC app socket
        Management packets are TODO

        For messages when key is NONE, we dont decrypt, else decrypt
        :return:
        """
        # QGroundControl binds to port 14550 upon start, thus forward all of our received messages to there.
        # This method is used to capture the broadcast from the drone and hand it to the QGC program
        while True:
            if not self.input.empty():
                msg = self.input.get(False)
                if self.currentSecret is not None:
                    self.decrypt(msg[0:-16], msg[-16:])
                if int.from_bytes(msg[0], "big") == 0:
                    # broadcast
                    pass
                if int.from_bytes(msg[0], "big") == 3:
                    # this message is a standard mavlink message, pass it on
                    # Send the mavlink message to QGC excluding the message type[0] and ID[1-2]
                    self.QGC_Socket.sendto(msg[3:].decode('utf-8'), self.QGC_Addr)
                    # For the drone, this information needs to be decoded then sent via serial to the flight controller
                    # This means that the drone should also respond with an ACK with the mavlink ID
                    #   ACK messages are a management message type, thus with ID 5
                elif int.from_bytes(msg[0], "big") == 4:
                    # code 5 is a management frame, this controls settings and retransmissions
                    # message format type[0], ID[1-2],managed type[3],context[4...]
                    # managed type 0 is an ACK, does not need an ACK response

                    # if we get an ACK for an ID, we search the reserve for this item and pull its timer object out
                    #   we then terminate the timer before deleting the message from the reserve
                    # TODO
                    if int.from_bytes(msg[3], "big") == 0:
                        # Got ACK
                        key = int.from_bytes(msg[4:], "big")
                        self.timers[key].cancel()
                    pass

    async def self_RX(self):
        """
        This method handles receiving the packets sent from QGC to the drone when used as a ground control station.
        Due to our use of the loopback address in broadcasts, QGC will send its messages to that address
        We thus bind to one of the ports QGC uses on the loopback adaptor to collect these packets
        The packets are then wrapped with the message type (mavlink:4) and device ID before broadcasting
        :return:
        """
        TX_Bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        TX_Bridge.bind(("127.0.0.1", 52796))  # bind to the local port QGC will send data to
        while True:
            msg = bytearray(284)
            TX_Bridge.recv_into(msg)
            msg = msg.rstrip(b'\x00')
            msg = b'4' + self.ID.encode() + msg
            # push the QGC message to the wireless interface with added message code and self ID
            self.outputStream.write(msg)
            await asyncio.sleep(0.01)
        pass

    def timer(self, messageType, messageID, messageContents):
        time.sleep(0.1)
        print("Timer triggered")
        asyncio.run(self.reSend(messageType, messageID, messageContents))

    def send(self, messageType, messageContents, needAck=True):
        """

        :param messageType: [Int]
        :param messageContents: [ByteArray]
        :param needAck: [Bool]
        :return:
        """
        encodedMsg = bytearray()
        encodedMsg.extend(messageType.to_bytes(1, "big"))
        encodedMsg.extend(self.messageID.to_bytes(2, "big"))  # 2 byte value, ID's from 0-65536
        encodedMsg.extend(messageContents)

        if self.currentSecret is None:
            # No set encryption, broadcast in the clear
            sendp(self.dataFrame / Raw(load=encodedMsg), iface=self.interface)
            pass
        else:
            sendp(self.dataFrame / Raw(load=self.encrypt(encodedMsg)), iface=self.interface)
            pass
        if needAck:
            # Finally, create a timer object with the ID of the message
            timer = self.timerPool.submit(self.timer, messageType, self.messageID, messageContents)
            self.timers[self.messageID] = timer
            # increment the counter, so it is ready for the next message
        self.messageID += 1

    async def reSend(self, messageType, ID, messageContents):
        encodedMsg = bytearray()
        encodedMsg.extend(messageType.to_bytes(1, "big"))
        encodedMsg.extend(self.messageID.to_bytes(2, "big"))  # 2 byte value, ID's from 0-65536
        encodedMsg.extend(messageContents)
        if self.currentSecret is None:
            # No set encryption, broadcast in the clear
            sendp(self.dataFrame / Raw(load=encodedMsg), iface=self.interface)
            pass
        else:
            sendp(self.dataFrame / Raw(load=self.encrypt(encodedMsg)), iface=self.interface)
            pass

    def handshake(self):
        # ID is of size 3 FIXED
        # Step 0, generate keys
        # self.keys = ECC.generate(curve='p256')

        self.ownKey = ec.generate_private_key(self.curve)

        # General message format: MessageType,ID,Contents, [1:3:n]bytes

        # Step 1, broadcast information
        # Initial handshake, broadcast your identity, public key, and channel

        # This can be augmented with signatures linked to the ID, fixed message is encrypted using their private key
        msg = bytearray()
        id = 0
        msg.extend(id.to_bytes(1, "big"))
        msg.extend(self.ID.encode())
        msg.extend(self.channel.to_bytes(1, "big"))
        msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                         format=serialization.PublicFormat.OpenSSH))

        sendp(self.dataFrame / Raw(load=msg), iface=self.interface)
        # Step 2, listen for either a broadcast or broadcast response
        while True:
            if not self.input.empty():
                pkt = self.input.get(False)
                msg = pkt[Raw].load
                if self.currentSecret is not None:
                    # if a key is active, try to decrypt the message
                    msg = self.decrypt(msg[0:-16], msg[-16:])
                if msg is not None:
                    # Data is valid, process as normal
                    print("Message Type: ", int.from_bytes(msg[0:1], "big"))
                    if int.from_bytes(msg[0:1], "big") == 0:
                        print("Got broadcast from: " + msg[1:4].decode() + " on channel: ", int.from_bytes(msg[4], "big"))
                        self.target = msg[1:4].decode()
                        # Step 3, extract public key
                        self.targetKey = serialization.load_ssh_public_key(msg[5:])

                        # Got a broadcast, respond with ID, pubKey

                        msg = bytearray()
                        msg.extend(self.ID.encode())
                        msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                         format=serialization.PublicFormat.OpenSSH))
                        self.send(1, msg)
                        # Finally, create a timer object with the ID of the message
                        timer = self.timerPool.submit(self.timer, 1, self.messageID, str(self.ID) + str(
                            self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                  format=serialization.PublicFormat.OpenSSH)))
                        self.timers[self.messageID] = timer
                        # increment the counter, so it is ready for the next message
                        self.messageID += 1
                        print("Responded with own data....")

                        # Generate initial shared secret
                        sharedSecret = self.ownKey.exchange(ec.ECDH(), self.targetKey)
                        self.masterSecret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                                 info=b'handshake data', ).derive(sharedSecret)

                        # Generate a proper key, using a fixed salt for now, possibility of adding a future change
                        self.currentSecret = scrypt(self.masterSecret, '0', 32, 1024, 8, 1)

                        # Now wait for the target to respond first, goto step 5

                    elif int.from_bytes(msg[0:1], "big") == 1:
                        # send back an ACK message
                        resp = bytearray()
                        resp.extend(b'0')
                        resp.extend(msg[1:3])
                        self.send(4, resp, False)

                        print("Got response from " + msg[3:5].decode())
                        self.target = msg[3:5].decode()
                        # Step 4, generate shared secret
                        self.targetKey = serialization.load_ssh_public_key(msg[5:])
                        sharedSecret = self.ownKey.exchange(ec.ECDH(), self.targetKey)
                        self.masterSecret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                                 info=b'handshake data', ).derive(sharedSecret)
                        # Generate a proper key, using a fixed salt for now, possibility of adding a future change
                        self.currentSecret = scrypt(self.masterSecret, '0', 32, 1024, 8, 1)
                        # Now broadcast an encrypted message back to the other device
                        # This message consists of the concatenation of the device ID's and the current channel
                        msg = bytearray()
                        msg.extend(self.target.encode())
                        msg.extend(self.ID.encode())
                        msg.extend(self.channel.to_bytes(1,"big"))
                        self.send(2, msg)
                        print("Sent cipher authentication msg")
                    elif int.from_bytes(msg[0:1], "big") == 2:
                        # Step 5, verify that the encryption keys are correct
                        print("STEP 2")
                        if msg[1:].decode() == self.ID + self.target + self.channel:
                            print("KEY GOOD")
                            # Now respond with the same but inverted message
                            data = '2' + self.target + self.ID + self.channel
                            sendp(self.dataFrame / Raw(load=self.encrypt(data)), iface=self.interface)
                            break
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
