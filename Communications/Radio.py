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
        self.input.put_nowait(pkt[Raw].load)

    def wirelessReceiver(self):
        sniff(iface='wlan1', prn=self.inputHandler, filter="udp and host 127.0.0.1 and dst port " + str(self.recPort))

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
        self.handshakeFlag = False
        # Cryptography variables
        # Exchange variables
        self.curve = ec.SECP256R1()
        self.ownKey = None
        self.targetKey = None
        self.masterSecret = None
        # ChaCha20 variables
        self.currentSecret = None
        self.eEngine = None
        # Startup the radio listener thread
        self.listener = threading.Thread(target=self.wirelessReceiver)
        self.listener.start()
        # Upon initiating, attempt to connect to a second radio in order to exchange keys
        # Communications start by default on channel 36
        # Message ID's: 1 is handshake,
        if ID != "GCS":  # only broadcast if you are a Drone
            asyncio.create_task(self.handshake())

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
        while True:
            msg = await self.outputStream.read()
            if msg is None:
                await asyncio.sleep(0.01)
            else:
                # TODO: Wrap this data correctly with management IDs
                if (msg[3] == 0):
                    await self.send(3, msg, False)  # don't need an ack for the heartbeat
                else:
                    await self.send(3, msg)
                """ 
                If the packet is type 3 (mavlink) we should store it in the reserve under the mavlink ID
                we should also create and store a time in the retransmission store for this message
                If the timer triggers, it pulls the message from the linked store and re-transmits it
                """

    def ack(self, ID):
        code = 0
        resp = bytearray()
        resp.extend(code.to_bytes(1, "big"))
        resp.extend(ID)
        asyncio.create_task(self.send(4, resp, False))

    async def rx(self):
        """
        The main Receiver for the application will check the type of data received and then handle it accordingly
        There are 5 data types to handle:
        * 0: This is a handshake information broadcast by a secondary device. It includes public keys and an ID we can
        use to initiate a secure connection
        * 1: A handshake broadcast response indicates that the secondary device has our public key information and
        wishes to initiate a secure channel. This includes the second devices key and ID
        * 2: This is a key authentication message. It will be encrypted containing our ID, their ID, and our current
        channel. If we are able to decrypt this information, and it matches our expectations, we know our derived keys
        are good, and thus we respond with and acknowledgement
        * 3: This is a standard mavlink packet, we simply need to remove the message type and ID [0-2] from the front of
        the packet before passing it to QGC
        * 4: This is a management packet, it could be a simple ACK message to one of our earlier messages, or
        information requesting device changes such as the wireless channel.
        :return:
        """
        # QGroundControl binds to port 14550 upon start, thus forward all of our received messages to there.
        # This method is used to capture the broadcast from the drone and hand it to the QGC program
        while True:
            if not self.input.empty():
                msg = self.input.get(False)
                # need way to check both encrypted and decrypted
                if self.currentSecret is not None:
                    decMsg = self.decrypt(msg[0:-16], msg[-16:])
                    if decMsg is not None:  # if decrypted properly, make msg the decrypted value
                        msg = decMsg
                        # this means that if we receive data such as ACK after keys are set, we can still process them
                if int.from_bytes(msg[0:1], "big") == 0 and not self.handshakeFlag:
                    # Received broadcast message, respond with our key and ID data
                    self.ack(msg[1:3])
                    print("Got broadcast from: " + msg[4:7].decode() + " on channel: ", msg[7])
                    self.timers["handshake"] = asyncio.create_task(self.resetHandshake())

                    self.target = msg[4:7].decode()
                    # Step 3, extract public key
                    self.targetKey = serialization.load_ssh_public_key(msg[8:])

                    # Got a broadcast, respond with ID, pubKey

                    msg = bytearray()
                    msg.extend(self.ID.encode())
                    msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                                     format=serialization.PublicFormat.OpenSSH))
                    await self.send(1, msg)
                    print("Responded with own data....")

                    # Generate initial shared secret
                    sharedSecret = self.ownKey.exchange(ec.ECDH(), self.targetKey)
                    self.masterSecret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                             info=b'handshake data', ).derive(sharedSecret)

                    # Generate a proper key, using a fixed salt for now, possibility of adding a future change
                    self.currentSecret = scrypt(self.masterSecret, '0', 32, 1024, 8, 1)

                    # Now wait for the target to respond first, goto step 5

                elif int.from_bytes(msg[0:1], "big") == 1 and not self.handshakeFlag:
                    # Received broadcast response, generate derived key and send auth message
                    self.ack(msg[1:3])
                    print("Got response from " + msg[3:6].decode())
                    self.timers["handshake"] = asyncio.create_task(self.resetHandshake())

                    self.target = msg[3:6].decode()
                    # Step 4, generate shared secret
                    self.targetKey = serialization.load_ssh_public_key(msg[6:])
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
                    msg.extend(self.channel.to_bytes(1, "big"))
                    await self.send(2, msg, False)  # No auth needed, if there is any response it is an auth
                    print("Sent cipher authentication msg")

                elif int.from_bytes(msg[0:1], "big") == 2 and not self.handshakeFlag:
                    self.ack(msg[1:3])
                    # Step 5, verify that the encryption keys are correct
                    print("STEP 2")
                    if msg[3:-1].decode() == self.ID + self.target and msg[-1] == self.channel:  # confirm and respond
                        print("KEY GOOD + RESPONDING")
                        self.handshakeFlag = True
                        self.timers["handshake"].cancel()
                        # Now respond with the same but inverted message
                        zero = 0
                        msg = bytearray()
                        msg.extend(self.target.encode())
                        msg.extend(self.ID.encode())
                        msg.extend(zero.to_bytes(1, "big"))
                        await self.send(2, msg)
                    elif msg[3:-1].decode() == self.ID + self.target and msg[-1] == 0:  # confirm without response
                        print("KEY GOOD")
                        self.handshakeFlag = True
                        self.timers["handshake"].cancel()
                    else:
                        print("KEY BAD")
                        # for a bad key scenario, we are unable to send an ACK back
                        # once the other side times out on resending, they should reset their keys and restart

                elif int.from_bytes(msg[0:1], "big") == 3 and self.handshakeFlag:
                    self.ack(msg[1:3])
                    # this message is a standard mavlink message, pass it on
                    # Send the mavlink message to QGC excluding the message type[0] and ID[1-2]
                    self.QGC_Socket.sendto(msg[3:], self.QGC_Addr)
                    # For the drone, this information needs to be decoded then sent via serial to the flight controller
                    # This means that the drone should also respond with an ACK with the mavlink ID
                    #   ACK messages are a management message type, thus with ID 5

                elif int.from_bytes(msg[0:1], "big") == 4:
                    # management message
                    if msg[3] == 0:
                        # Got ACK
                        key = int.from_bytes(msg[4:], "big")
                        try:
                            timer = self.timers.pop(key)
                            while not timer.cancel():
                                timer = self.timers.pop(key)
                                await asyncio.sleep(0.0001)
                            print("Terminated timer successfully")
                        except KeyError:
                            pass
                    else:
                        self.ack(msg[1:3])
            else:
                await asyncio.sleep(0.01)

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
        TX_Bridge.setblocking(False)
        while True:
            try:
                msg = bytearray(284)
                TX_Bridge.recv_into(msg)
                msg = msg.rstrip(b'\x00')
                msg = b'4' + self.ID.encode() + msg
                # push the QGC message to the wireless interface with added message code and self ID
                self.outputStream.write(msg)
            except Exception:
                await asyncio.sleep(0.01)
        pass

    async def send(self, messageType, messageContents, needAck=True):
        """
        This method manages sending data via SCAPY in the correct way.
        Serialisation:
            [0] : The first byte is always the packet type, this can be 0-4, representing handshake packets 0-2, or
            mavlink (3), or management (4) frames
            [1,2] : The second and third bytes are the ID values for the packet, allowing each to be uniquely identified
            [3:-1] : bytes 3 onwards is the main content of the packet
        for each packet sent, we can select if it needs an acknowledgment message. If this is true, as it is by default,
        the method will create a new asynchronous task that will trigger the re-send method with the same data after a
        designated time. If an ACK is received before this time, the object can be fetched from the self.timers
        dictionary and canceled

        :param messageType: [Int] Data identifying the packet type
        :param messageContents: [ByteArray] The contents of the packet
        :param needAck: [Bool]: A flag that will determine if the system will need an ACK or not to confirm receipt
        :return:
        """
        encodedMsg = bytearray()
        encodedMsg.extend(messageType.to_bytes(1, "big"))
        encodedMsg.extend(self.messageID.to_bytes(2, "big"))  # 2 byte value, ID's from 0-65536
        encodedMsg.extend(messageContents)

        if self.currentSecret is None:
            # No set encryption, broadcast in the clear
            sendp(self.dataFrame / Raw(load=encodedMsg), iface=self.interface, verbose=0)
            pass
        else:
            sendp(self.dataFrame / Raw(load=self.encrypt(encodedMsg)), iface=self.interface, verbose=0)
            pass
        if needAck:
            # Finally, create a timer object with the ID of the message
            timer = asyncio.create_task(self.timer(messageType, self.messageID, messageContents))
            self.timers[self.messageID] = timer
            # increment the counter, so it is ready for the next message
        self.messageID += 1

    async def reSend(self, messageType, ID, messageContents, attempts):
        """
        The re-send method is functionally identical to the send method except it will take a fixed message ID of the
        old message rather than generating a new one. We can also check how many more times to attempt to send this
        message
        :param messageType: [Int] Data identifying the packet type
        :param ID: [Int] 2 bytes that make up the ID of the message
        :param messageContents: [ByteArray] The contents of the packet
        :param attempts: [Int] The remaining attempts to re-send
        :return:
        """
        encodedMsg = bytearray()
        encodedMsg.extend(messageType.to_bytes(1, "big"))
        encodedMsg.extend(ID.to_bytes(2, "big"))  # 2 byte value, ID's from 0-65536
        encodedMsg.extend(messageContents)
        if self.currentSecret is None:
            # No set encryption, broadcast in the clear
            sendp(self.dataFrame / Raw(load=encodedMsg), iface=self.interface, verbose=0)
            pass
        else:
            sendp(self.dataFrame / Raw(load=self.encrypt(encodedMsg)), iface=self.interface, verbose=0)
            pass
        attempts += -1
        if attempts >= 1:
            timer = asyncio.create_task(self.timer(messageType, ID, messageContents, attempts))
            self.timers[self.messageID] = timer

    async def timer(self, messageType, messageID, messageContents, duration=0.1, attempts=5):
        """
        The timer method allows us to create asynchronous tasks to trigger a re-send action if the other device does not
        acknowledge a message in time.
        :param messageType: [Int] the type of message
        :param messageID: [Int] 2 bytes that make up the ID of the message
        :param messageContents: [ByteArray] the payload of the overall message
        :param duration: [Float] The time to wait before triggering a re-send in seconds
        :param attempts: [Int] The number of times to try to re-send
        :return:
        """
        # TOD: Check why the channel value of the broadcast disappears when re-sending
        await asyncio.sleep(duration)
        print("Timer triggered")
        await self.reSend(messageType, messageID, messageContents, attempts)
        await asyncio.sleep(0.0001)

    async def handshake(self):
        """
        The handshake method kicks off a cryptographical handshake between two devices to establish a secure channel
        Initially we simply create our own key pair and broadcast connection information in the clear
        :return:
        """
        # Step 0, generate keys
        self.ownKey = ec.generate_private_key(self.curve)

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
        await self.send(0, msg, False)

    async def resetHandshake(self):
        """
        Reset handshake is a simple timeout method created as soon as a handshake is initiated with a second device
        This ensures that our handshake cannot hang and in the case of malformed keys all the data is flushed before
        a new handshake is attempted
        :return:
        """
        await asyncio.sleep(5)  # 5 seconds allocated for a successful handshake
        self.masterSecret = None
        self.currentSecret = None
        self.target = None
        self.targetKey = None

        msg = bytearray()
        msg.extend(self.ID.encode())
        msg.extend(self.channel.to_bytes(1, "big"))
        msg.extend(self.ownKey.public_key().public_bytes(encoding=serialization.Encoding.OpenSSH,
                                                         format=serialization.PublicFormat.OpenSSH))
        await self.send(0, msg, False)

    def getHandshakeStatus(self):
        return self.handshakeFlag
