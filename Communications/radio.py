import asyncio
import multiprocessing
import queue
import socket
import subprocess
from multiprocessing import Process
import time

import scapy.interfaces

from Crypto.Protocol.KDF import scrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Encryption Imports
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from scapy.all import sendp, sniff
from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw


# from main import inputStream


class Radio:
    def input_handler(self, pkt):
        # Possibly add address filtering at this layer
        self.packet_inbox.put_nowait(pkt[Raw].load)

    def stop_filter(self, _):
        return self.running is False

    def wireless_receiver(self):
        scapy.interfaces.ifaces.reload()
        sniff(
            iface="wlan1",
            prn=self.input_handler,
            filter="udp and host 127.0.0.1",
            stop_filter=self.stop_filter,
        )

    # noinspection too-many-positional-arguments
    def __init__(
            self,
            output_stream,
            input_stream,
            vehicle_id,
            channel,
            port,
            interface="wlan1",
    ):
        self._current_secret = None
        self._encryption_engine = None
        self.interface = interface
        self.packet_outbox = output_stream
        self.packet_inbox = input_stream
        self.qgc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.qgc_addr = ("127.0.0.1", 14550)
        self.rec_port = int(port)
        self.dest_port = int(port)
        self.data_frame = (
                RadioTap()
                / Dot11(
            addr1="00:00:00:00:00:00",
            addr2="00:00:00:00:00:00",
            addr3="00:00:00:00:00:00",
            type=2,
            subtype=8,
        )
                / Dot11QoS(TXOP=4, Ack_Policy=1)
                / LLC()
                / SNAP()
                / IP(src="127.0.0.1", dst="127.0.0.1")
                / UDP(sport=self.rec_port, dport=self.dest_port)
        )

        # Identity variables
        self.id = vehicle_id
        self.target = None
        self.channel = int(channel)
        # Management stores
        self.reserve = {}
        self.timers = {}
        self.message_id = 0
        self.handshake_flag = False
        # Cryptography variables
        # Exchange variables
        self.curve = ec.SECP256R1()
        # Step 0, generate keys
        self.own_key = ec.generate_private_key(self.curve)
        self.target_key = None
        self.master_secret = None
        # ChaCha20 variables
        self.current_secret = None
        self.encryption_engine = None
        # Startup the radio listener thread
        self.listener = Process(target=self.wireless_receiver)
        self.running = True
        self.listener.start()

    def send(self, message_contents, need_ack=True):
        """
        This method manages sending data via SCAPY in the correct way.
        :param message_contents: [ByteArray] The contents of the packet
        :param need_ack: [Bool]: A flag that will determine if the system will need an ACK or not to confirm receipt
        :return:
        """
        sendp(
            self.data_frame / Raw(load=message_contents), iface=self.interface, verbose=0
        )
        if need_ack:
            # Finally, create a timer object with the ID of the message
            timer_id = self.message_id
            timer = asyncio.create_task(
                self.timer(message_contents, timer_id)
            )
            self.timers[timer_id] = timer

            # increment the counter, so it is ready for the next message
        self.message_id += 1
        print("Send done")

    async def timer(self, message_contents, message_id, duration=0.25, attempts=5):
        """
        The timer method allows us to create asynchronous tasks to trigger a re-send action if the other device does not
        acknowledge a message in time.
        :param message_contents: [ByteArray] the payload of the overall message
        :param message_id: [Int] the id of the message
        :param duration: [Float] The time to wait before triggering a re-send in seconds
        :param attempts: [Int] The number of times to try to re-send
        :return:
        """
        # TOD: Check why the channel value of the broadcast disappears when
        # re-sending
        await asyncio.sleep(duration)
        print("Timer ", message_id, " triggered, remaining attempts:",attempts)
        self.re_send(message_contents, message_id, attempts)

    def re_send(self, message_contents, message_id ,attempts):
        """
        The re-send method is functionally identical to the send method except it will take a fixed message ID of the
        old message rather than generating a new one. We can also check how many more times to attempt to send this
        message

        :param message_contents: [ByteArray] The contents of the packet
        :param message_id: [Int] The id of the packet
        :param attempts: [Int] The remaining attempts to re-send
        :return:
        """
        sendp(
            self.data_frame / Raw(load=message_contents), iface=self.interface, verbose=0
        )
        attempts -= 1
        if attempts >= 1:
            timer = asyncio.create_task(
                self.timer(message_contents, message_id, attempts=attempts)
            )
            self.timers[message_id] = timer
        else:
            print("Timer completed")



    def end(self):
        print("Trying to end")
        self.running = False
        # wait 2 seconds to see if the thread joined
        self.listener.join(timeout=2)
        if self.listener.is_alive():
            # force shutdown by breaking the sniff object
            self.listener.kill()
            print("Forcefully resetting the wireless adapter, you will see a warning:")
            subprocess.check_output(
                ["sudo", "ip", "link", "set", self.interface, "down"]
            )
            time.sleep(0.5)
            subprocess.check_output(["sudo", "ip", "link", "set", self.interface, "up"])
        print("Listener done")

########################################################################################################################
    async def tx(self):
        """
        The Transmission method is used by the drone mainly. This will take the packets sent via the vehicle object
        and then send them via the wireless interface
        :return:
        """
        while self.running:
            msg = self.packet_outbox.read()
            if msg is None:
                await asyncio.sleep(0.01)
            else:
                # Wrap this data correctly with management IDs
                if msg[3] == 0:
                    # don't need an ack for the heartbeat
                    self.send(3, msg, False)
                else:
                    self.send(3, msg)

                # If the packet is type 3 (mavlink) we should store it in the reserve under the mavlink ID
                # we should also create and store a time in the retransmission store for this message
                # If the timer triggers, it pulls the message from the linked store and re-transmits it

    def ack(self, message_id):
        print("Sending ack for message id " + message_id)
        code = 0
        resp = bytearray()
        resp.extend(code.to_bytes(1, "big"))
        resp.extend(message_id)
        self.send(resp, False)

    # noinspection too-many-branches
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
        # This method is used to capture the broadcast from the drone and hand
        # it to the QGC program
        while self.running:
            if not self.packet_inbox.empty():
                msg = self.packet_inbox.get(False)
                # need way to check both encrypted and decrypted
                if self.current_secret is not None:
                    dec_msg = self.decrypt(msg[0:-16], msg[-16:])
                    if (
                            dec_msg is not None
                    ):  # if decrypted properly, make msg the decrypted value
                        msg = dec_msg
                        # this means that if we receive data such as ACK after
                        # keys are set, we can still process them
                if int.from_bytes(msg[0:1], "big") == 0 and not self.handshake_flag:
                    # Received broadcast message, respond with our key and ID
                    # data
                    self.ack(msg[1:3])
                    print(
                        "Got broadcast from: " + msg[4:7].decode() + " on channel: ",
                        msg[7],
                    )
                    self.timers["handshake"] = asyncio.create_task(
                        self.reset_handshake()
                    )

                    self.target = msg[4:7].decode()
                    # Step 3, extract public key
                    self.target_key = serialization.load_ssh_public_key(msg[8:])

                    # Got a broadcast, respond with ID, pubKey

                    msg = bytearray()
                    msg.extend(self.id.encode())
                    msg.extend(
                        self.own_key.public_key().public_bytes(
                            encoding=serialization.Encoding.OpenSSH,
                            format=serialization.PublicFormat.OpenSSH,
                        )
                    )
                    self.send(1, msg)
                    print("Responded with own data....")

                    # Generate initial shared secret
                    shared_secret = self.own_key.exchange(ec.ECDH(), self.target_key)
                    self.master_secret = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"handshake data",
                    ).derive(shared_secret)

                    # Generate a proper key, using a fixed salt for now,
                    # possibility of adding a future change
                    self.current_secret = scrypt(
                        self.master_secret, "0", 32, 1024, 8, 1
                    )

                    # Now wait for the target to respond first, goto step 5

                elif int.from_bytes(msg[0:1], "big") == 1 and not self.handshake_flag:
                    # Received broadcast response, generate derived key and
                    # send auth message
                    self.ack(msg[1:3])
                    print("Got response from " + msg[3:6].decode())
                    self.timers["handshake"] = asyncio.create_task(
                        self.reset_handshake()
                    )

                    self.target = msg[3:6].decode()
                    # Step 4, generate shared secret
                    self.target_key = serialization.load_ssh_public_key(msg[6:])
                    shared_secret = self.own_key.exchange(ec.ECDH(), self.target_key)
                    self.master_secret = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"handshake data",
                    ).derive(shared_secret)
                    # Generate a proper key, using a fixed salt for now,
                    # possibility of adding a future change
                    self.current_secret = scrypt(
                        self.master_secret, "0", 32, 1024, 8, 1
                    )
                    # Now broadcast an encrypted message back to the other device
                    # This message consists of the concatenation of the device
                    # ID's and the current channel
                    msg = bytearray()
                    msg.extend(self.target.encode())
                    msg.extend(self.id.encode())
                    msg.extend(self.channel.to_bytes(1, "big"))
                    # No auth needed, if there is any response it is an auth
                    self.send(2, msg, False)
                    print("Sent cipher authentication msg")

                elif int.from_bytes(msg[0:1], "big") == 2 and not self.handshake_flag:
                    self.ack(msg[1:3])
                    # Step 5, verify that the encryption keys are correct
                    print("STEP 2")
                    if (
                            msg[3:-1].decode() == self.id + self.target
                            and msg[-1] == self.channel
                    ):  # confirm and respond
                        print("KEY GOOD + RESPONDING")
                        self.handshake_flag = True
                        self.timers["handshake"].cancel()
                        # Now respond with the same but inverted message
                        zero = 0
                        msg = bytearray()
                        msg.extend(self.target.encode())
                        msg.extend(self.id.encode())
                        msg.extend(zero.to_bytes(1, "big"))
                        self.send(2, msg)
                    # confirm without response
                    elif msg[3:-1].decode() == self.id + self.target and msg[-1] == 0:
                        print("KEY GOOD")
                        self.handshake_flag = True
                        self.timers["handshake"].cancel()
                    else:
                        print("KEY BAD")
                        # for a bad key scenario, we are unable to send an ACK back
                        # once the other side times out on resending, they
                        # should reset their keys and restart

                elif int.from_bytes(msg[0:1], "big") == 3 and self.handshake_flag:
                    self.ack(msg[1:3])
                    # this message is a standard mavlink message, pass it on
                    # Send the mavlink message to QGC excluding the message
                    # type[0] and ID[1-2]
                    self.qgc_socket.sendto(msg[3:], self.qgc_addr)
                    # For the drone, this information needs to be decoded then sent via serial to the flight controller
                    # This means that the drone should also respond with an ACK with the mavlink ID
                    # ACK messages are a management message type, thus with ID
                    # 5

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

    async def self_rx(self):
        """
        This method handles receiving the packets sent from QGC to the drone when used as a ground control station.
        Due to our use of the loopback address in broadcasts, QGC will send its messages to that address
        We thus bind to one of the ports QGC uses on the loopback adaptor to collect these packets
        The packets are then wrapped with the message type (mavlink:4) and device ID before broadcasting
        :return:
        """
        tx_bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # bind to the local port QGC will send data to
        tx_bridge.bind(("127.0.0.1", 52796))
        tx_bridge.setblocking(False)
        while True:
            msg = bytearray(284)
            tx_bridge.recv_into(msg)
            msg = msg.rstrip(b"\x00")
            msg = b"4" + self.id.encode() + msg
            # push the QGC message to the wireless interface with added
            # message code and self ID
            self.packet_outbox.write(msg)

    async def handshake(self):
        """
        The handshake method kicks off a cryptographical handshake between two devices to establish a secure channel
        Initially we simply create our own key pair and broadcast connection information in the clear
        :return:
        """

        # Step 1, broadcast information
        # Initial handshake, broadcast your identity, public key, and channel
        # This can be augmented with signatures linked to the ID, fixed message
        # is encrypted using their private key
        msg = bytearray()
        message_id = 0
        msg.extend(message_id.to_bytes(1, "big"))
        msg.extend(self.id.encode())
        msg.extend(self.channel.to_bytes(1, "big"))
        msg.extend(
            self.own_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )
        self.send(0, msg, False)

        while self.target_key is None:
            await asyncio.sleep(10)
            self.send(0, msg, False)

    async def reset_handshake(self):
        """
        Reset handshake is a simple timeout method created as soon as a handshake is initiated with a second device
        This ensures that our handshake cannot hang and in the case of malformed keys all the data is flushed before
        a new handshake is attempted
        :return:
        """
        await asyncio.sleep(5)  # 5 seconds allocated for a successful handshake
        self.master_secret = None
        self.current_secret = None
        self.target = None
        self.target_key = None

        msg = bytearray()
        msg.extend(self.id.encode())
        msg.extend(self.channel.to_bytes(1, "big"))
        msg.extend(
            self.own_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )
        self.send(0, msg, False)

    def get_handshake_status(self):
        return self.handshake_flag


