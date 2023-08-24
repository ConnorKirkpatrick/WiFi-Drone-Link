import asyncio

from pymavlink.dialects.v20 import common as mavlink2


class messages:
    def __init__(self, vehicle):
        self.vehicle = vehicle

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
