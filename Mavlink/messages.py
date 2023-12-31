import asyncio
import struct

from pymavlink.dialects.v20 import common as mavlink2


class messages:
    def __init__(self, vehicle):
        self.vehicle = vehicle
        asyncio.create_task(self.heartBeat())

    async def heartBeat(self):
        """
        Heartbeat of the vehicle, covers the status of the system and type. Is broadcast at 1Hz
        :param vehicle:
        :return:
        """
        while True:
            self.vehicle.heartbeat_send(mavlink2.MAV_TYPE_HEXAROTOR, mavlink2.MAV_AUTOPILOT_PX4,
                                        mavlink2.MAV_MODE_FLAG_TEST_ENABLED,
                                        mavlink2.MAV_MODE_FLAG_TEST_ENABLED, mavlink2.MAV_STATE_STANDBY)
            await asyncio.sleep(1)

    async def GPS_Raw(self):
        """
        GPS data for the vehicle. This includes data such as the position, time, and number of satellites
        This is sent at about 4Hz
        :param vehicle:
        :return:
        """
        while True:
            self.vehicle.gps_raw_int_send(0, mavlink2.GPS_FIX_TYPE_2D_FIX, 513438446, -6432654, 120, 65535, 65535, 0, 0,
                                          10, 150,
                                          0, 0, 0, 0, 0)
            await asyncio.sleep(0.25)

    async def statustext(self, message):
        print(message[1:])
        self.vehicle.statustext_send(message[0], message[1:])

    async def GPS(self):
        while True:
            self.vehicle.global_position_int_send(2000, 513438508, -6432654, 110, 0, 0, 0, 0, 90)

    async def GlobalPosition(self,message):
        time = int.from_bytes(message[0:4],"little",signed=False)
        lat = int.from_bytes(message[4:8],"little",signed=True)
        lng = int.from_bytes(message[8:12],"little",signed=True)
        alt = int.from_bytes(message[12:16],"little",signed=True)
        ralt = int.from_bytes(message[16:20],"little",signed=True)
        vx = int.from_bytes(message[20:22],"little",signed=True)
        vy = int.from_bytes(message[22:24],"little",signed=True)
        vz = int.from_bytes(message[24:26],"little",signed=True)
        hdg = int.from_bytes(message[26:28],"little",signed=False)
        self.vehicle.global_position_int_send(time,lat,lng,alt,ralt,vx,vy,vz,hdg)

    async def Attitude(self,message):
        time = int.from_bytes(message[0:4],"little",signed=False)
        roll = struct.unpack("f",message[4:8])
        pitch = struct.unpack("f", message[8:12])
        yaw = struct.unpack("f", message[12:16])

        rollR = struct.unpack("f", message[16:20])
        pitchR = struct.unpack("f", message[20:24])
        yawR = struct.unpack("f", message[24:28])
        self.vehicle.attitude_send(time,roll,pitch,yaw,rollR,pitchR,yawR)

    async def GPS_Raw(self, message):
        time = int.from_bytes(message[0:8],"little",signed=False)
        fix = time = int.from_bytes(message[8],"little",signed=False)
        lat = int.from_bytes(message[9:13],"little",signed=True)
        lng = int.from_bytes(message[13:17],"little",signed=True)
        alt = int.from_bytes(message[17:21], "little", signed=True)
        hdop = int.from_bytes(message[21:23], "little", signed=False)
        vdop = int.from_bytes(message[23:25], "little", signed=False)
        crs = int.from_bytes(message[25:27],"little",signed=False)
        sats = int.from_bytes(message[27],"little",signed=False)
        Ealt = int.from_bytes(message[28:32],"little",signed=True)
        hu = int.from_bytes(message[32:36],"little",signed=False)
        vu = int.from_bytes(message[36:40], "little", signed=False)
        velU = int.from_bytes(message[40:44],"little",signed=False)
        headU = int.from_bytes(message[44:48],"little",signed=False)
        yaw = int.from_bytes(message[48:50], "little", signed=False)
        self.vehicle.gps_raw_int_send(time,fix,lat,lng,alt,hdop,vdop,crs,sats,Ealt,hu,vu,velU,headU,yaw)
