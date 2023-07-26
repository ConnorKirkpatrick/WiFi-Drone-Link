import asyncio, time

from pymavlink.dialects.v20 import common as mavlink2


async def heartBeat(vehicle):
    while True:
        vehicle.heartbeat_send(mavlink2.MAV_TYPE_HEXAROTOR, mavlink2.MAV_AUTOPILOT_PX4,
                               mavlink2.MAV_MODE_FLAG_TEST_ENABLED,
                               mavlink2.MAV_MODE_FLAG_TEST_ENABLED, mavlink2.MAV_STATE_STANDBY)
        vehicle.send
        await asyncio.sleep(1)
