import asyncio
import time

import serial


class Serial_Connection:
    def __init__(self, port, messenger):
        self.serial = serial.Serial(port, 115200, timeout=0.1)
        self.messenger = messenger
        self.initiate()
        self.write(0, "YYYYY")
        print("SERIAL READY")
        asyncio.create_task(self.handler())

    def read(self):
        if self.serial.inWaiting() > 0:
            size = self.serial.read(1)
            data = self.serial.read(int.from_bytes(size, "big"))
            return data
        else:
            return False

    def write(self, ID, msg):
        size = msg.__len__() + 1
        data = bytearray()
        data.extend(size.to_bytes(1, "big"))
        data.extend(ID.to_bytes(1, "big"))
        data.extend(bytes(msg, "utf-8"))
        self.serial.write(bytes(data))

    def initiate(self):
        while True:
            data = self.read()
            if data is not False:
                if data[0] == 0 and data[1:] == b'XXXXX':
                    break
            time.sleep(0.001)

    async def handler(self):
        while True:
            data = self.read()
            if not data:
                await asyncio.sleep(0.001)
            elif data[0] == 1:
                # this is as status text message
                await self.messenger.statustext(data[1:])
            elif data[0] == 2:
                await self.messenger.GlobalPosition(data[1:])
            elif data[0] == 3:
                await self.messenger.GPS_Raw(data[1:])
            elif data[0] == 4:
                await self.messenger.Attitude(data[1:])

#Todo: If gyro fails, disconnect serial and power cycle ports. Do the same if gyro calibrate takes >15s
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
