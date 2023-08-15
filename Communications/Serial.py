import serial


class Serial_Connection:
    def __init__(self, port):
        self.serial = serial.Serial(port, 115200, timeout=1)

    def read(self):
        return self.serial.readline()

    def write(self, msg):
        self.serial.write(msg)


"""
    Arduino FCS telemetry rates:
        GPS: 1hz
        Attitude: 2-5 hz
        Altitude: 2-5 hz
        battery status: 1 hz
        radio status: 1-2 hz
        virtual RC: >= 5 hz
        
    Radio mavlink communication protocol
        message sent includes ID
        RPI will hold that message in reserve
        recipient will respond with a management ACK of the message ID
        RPI can drop the message from reserve
        if message is still in reserve after set time, retransmission is made  
        this repeats up to retransmission limit, where the packet is not returned to reserve after re-transmission
        
        reserve is made of hash map/dictionary
"""
