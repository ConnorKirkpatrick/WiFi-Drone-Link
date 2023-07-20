from pymavlink.dialects.v20 import common as mavlink2
import asyncio, time, os
from Radios.TX import TX_Radio
from initialise import initialiseWiFi
import messageStore
from Mavlink import messages

async def main():
    initialiseWiFi()
    os.environ["MAVLINK20"] = '1'
    outputStream = messageStore.messageStore()

    vehicle = mavlink2.MAVLink(outputStream)
    TX = TX_Radio(outputStream)
    # Note: file is the address/device mavlink will try to transmit on. We will route this to our
    # own structure to allow us to encrypt and broadcast the message

    asyncio.create_task(TX.tx())
    asyncio.create_task(messages.heartBeat(vehicle))



    # mav.gps_raw_int_send()
    # mav.attitude_send()


if __name__ == '__main__':
    asyncio.run(main())
