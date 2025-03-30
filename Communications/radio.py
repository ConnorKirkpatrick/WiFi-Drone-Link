import asyncio
import socket
import subprocess
from multiprocessing import Process
import time

import scapy.interfaces

from cryptography.hazmat.primitives.asymmetric import ec

# Encryption Imports
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

    def get_next_id(self):
        return self.message_id

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

    def clear_timer(self, message_id):
        if message_id in self.timers:
            timer = self.timers[message_id]
            timer.cancel()
            del self.timers[message_id]
            print("Cleared timer",message_id)
            return True
        return False

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
