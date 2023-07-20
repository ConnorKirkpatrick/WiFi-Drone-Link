import asyncio

from scapy.all import sendp
from scapy.layers.dot11 import Dot11, Dot11QoS, RadioTap
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw


class TX_Radio:
    dataFrame = RadioTap() / Dot11(addr1="00:00:00:00:00:00",
                                   addr2="00:00:00:00:00:00",
                                   addr3="00:00:00:00:00:00",
                                   type=2,
                                   subtype=8) / Dot11QoS() / LLC() / SNAP() / IP(src='127.0.0.1',
                                                                                 dst='127.0.0.1') / UDP(
        sport=5000, dport=5001)
    seq = 0
    selfID = 255

    def __init__(self, data_stream, interface="wlan1"):
        self.interface = interface
        self.data = data_stream

    async def tx(self):
        msg = await self.data.read()
        print(msg)
        # sendp(self.dataFrame / Raw(load=msg), iface=self.interface)
        return 0

    async def rx(self):
        pass

# This segment of code can be used to observe if a probe request can be sent. If this is possible it means that the
# devices do support monitor mode with injection
# dot11 = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2='11:11:11:11:11:66',
# addr3='22:22:22:22:22:22') probeReq = Dot11ProbeReq() dot11elt = Dot11Elt() frame = RadioTap() / dot11 / probeReq /
# dot11elt sendp(frame, iface=interface)
