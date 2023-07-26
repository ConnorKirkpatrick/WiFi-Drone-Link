from scapy.layers.dot11 import RadioTap, Dot11
from scapy.sendrecv import sniff

interface = 'wlan1'

def packetHandler(pkt):
    if(pkt.haslayer(RadioTap) and pkt.haslayer(Dot11)):
        dot11 = pkt.getlayer(Dot11)
        if(dot11.addr2 == "11:11:11:11:11:11"):
            rssi = str(RadioTap.dBm_AntSignal)
            print("Received Probe Request with rssi = " + rssi)
            exit()

print("Starting sniff: ")
while True:
    sniff(iface=interface, prn=packetHandler, store=0)


# Mavlink is another layer inside UDP or TCP
# We have to fully define the packets we plan on using on the drone, there is no self-building function

# The TX class will keep note of all the standard MAVLINK packet data, such as packet ID and flags
# Calling transmit will hand the class the required message ID and payload to send
