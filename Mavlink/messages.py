import asyncio

from pymavlink.dialects.v20 import common as mavlink2


async def heartBeat(vehicle):
    while True:
        vehicle.heartbeat_send(mavlink2.MAV_TYPE_VTOL_TILTROTOR, mavlink2.MAV_AUTOPILOT_GENERIC,
                               mavlink2.MAV_MODE_PREFLIGHT,
                               mavlink2.MAV_MODE_PREFLIGHT, mavlink2.MAV_STATE_STANDBY)
        await asyncio.sleep(1)
