from pymavlink.dialects.v20 import common as mavlink2
import asyncio, time, os
from Radios.TX import TX_Radio
from initialise import initialiseWiFi
import messageStore


async def main():
    initialiseWiFi()
    os.environ["MAVLINK20"] = '1'
    outputStream = messageStore.messageStore()

    vehicle = mavlink2.MAVLink(outputStream)
    TX = TX_Radio(outputStream)
    # Note: file is the address/device mavlink will try to transmit on. We will route this to our
    # own structure to allow us to encrypt and broadcast the message

    # asyncio.run(TX.tx())

    vehicle.heartbeat_send(mavlink2.MAV_TYPE_VTOL_TILTROTOR, mavlink2.MAV_AUTOPILOT_GENERIC,
                           mavlink2.MAV_MODE_PREFLIGHT,
                           mavlink2.MAV_MODE_PREFLIGHT, mavlink2.MAV_STATE_STANDBY)
    # for each in outputStream.getvalue():
    #    print(each)
    # exit()
    time.sleep(0.1)
    vehicle.heartbeat_send(mavlink2.MAV_TYPE_VTOL_TILTROTOR, mavlink2.MAV_AUTOPILOT_GENERIC,
                           mavlink2.MAV_MODE_AUTO_ARMED,
                           mavlink2.MAV_MODE_AUTO_ARMED,
                           mavlink2.MAV_STATE_STANDBY)
    # mav.gps_raw_int_send()
    # mav.attitude_send()


if __name__ == '__main__':
    asyncio.run(main())
