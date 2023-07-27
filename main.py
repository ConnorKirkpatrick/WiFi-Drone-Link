from pymavlink.dialects.v20 import common as mavlink2
import asyncio, time, os
from threading import *
from Radios.TX import Radio
from initialise import initialiseWiFi
import messageStore
from Mavlink import messages

async def main():
    #initialiseWiFi()
    os.environ["MAVLINK20"] = '1'
    os.environ["SYS_ID"] = '1'
    outputStream = messageStore.messageStore()

    vehicle = mavlink2.MAVLink(outputStream, srcSystem=1, srcComponent=1)
    TX = Radio(outputStream)

    # Note: file is the address/device mavlink will try to transmit on. We will route this to our
    # own structure to allow us to encrypt and broadcast the message

    # Radio Tasks
    asyncio.create_task(TX.tx())
    asyncio.create_task(TX.self_RX(vehicle))

    # Mavlink tasks
    asyncio.create_task(messages.heartBeat(vehicle))
    asyncio.create_task(messages.GPS_Raw(vehicle))


    print("Tasks created")



    while True:
        await asyncio.sleep(1)


    # mav.gps_raw_int_send()
    # mav.attitude_send()


if __name__ == '__main__':
    asyncio.run(main())