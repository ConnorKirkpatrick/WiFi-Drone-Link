import asyncio, time

from pymavlink.dialects.v20 import common as mavlink2


async def heartBeat(vehicle):
    """
    Heartbeat of the vehicle, covers the status of the system and type. Is broadcast at 1Hz
    :param vehicle:
    :return:
    """
    while True:
        vehicle.heartbeat_send(mavlink2.MAV_TYPE_HEXAROTOR, mavlink2.MAV_AUTOPILOT_PX4,
                               mavlink2.MAV_MODE_FLAG_TEST_ENABLED,
                               mavlink2.MAV_MODE_FLAG_TEST_ENABLED, mavlink2.MAV_STATE_STANDBY)
        await asyncio.sleep(1)


async def GPS_Raw(vehicle):
    """
    GPS data for the vehicle. This includes data such as the position, time, and number of satellites
    This is sent at about 4Hz
    :param vehicle:
    :return:
    """
    while True:
        vehicle.gps_raw_int_send(0, mavlink2.GPS_FIX_TYPE_2D_FIX, 513438446, -6432654, 120, 65535, 65535, 0, 0, 10, 150,
                                 0, 0, 0, 0, 0)
        await asyncio.sleep(0.25)

async def GPS(vehicle):
    while True:
        vehicle.global_position_int_send(2000,513438508, -6432654,110,0,0,0,0,90)