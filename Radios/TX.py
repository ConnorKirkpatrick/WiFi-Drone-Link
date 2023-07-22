import asyncio, socket

from scapy.all import sendp, sniff
from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw

from messageStore import messageStore

RX_Bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
RX_IP = "127.0.0.1"
RX_PORT = 14550


async def packageHandler(pkt):
    if pkt.haslayer(IP) and pkt[IP].src == "127.0.0.1":
        print("Test Pass")
        print("Data: ")
        print(pkt[Raw].load)
        RX_Bridge.sendto(pkt[Raw].load, (RX_IP, RX_PORT))
    else:
        print("Test Fail")


class TX_Radio:
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

    async def tx(self):
        print("Started")
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
        while True:
            sniff(iface=self.interface, prn=packageHandler, store=0)
        pass
