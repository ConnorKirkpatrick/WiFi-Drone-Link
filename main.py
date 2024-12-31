import multiprocessing.queues

from pymavlink.dialects.v20 import common as mavlink2
import asyncio, os, queue
from Communications.Radio import Radio
from Communications.Serial import Serial_Connection
from Mavlink import messages
from initialise import initialiseWiFi, resetWiFi
import messageStore
from scapy.all import sniff

inputStream = multiprocessing.Queue()


async def main():
    try:
        print("Started")
        initialiseWiFi()
        os.environ["MAVLINK20"] = '1'
        # read settings from file
        config = open("config.txt", "r")
        ID = config.readline().split(":")[1].strip("\n")
        Interface = config.readline().split(":")[1].strip("\n")
        channel = config.readline().split(":")[1].strip("\n")
        recPort = config.readline().split(":")[1].strip("\n")
        decPort = config.readline().split(":")[1].strip("\n")
        config.close()

        outputStream = messageStore.messageStore()
        vehicle = mavlink2.MAVLink(outputStream, srcSystem=1, srcComponent=1)
        TX = Radio(vehicle, outputStream, inputStream, ID, channel, recPort, decPort, Interface)

        # Note: file is the address/device mavlink will try to transmit on. We will route this to our
        # own structure to allow us to encrypt and broadcast the message

        # Global tasks, start these for both ground station and drone
        #   Radio Tasks
        tx = asyncio.create_task(TX.tx())
        rx = asyncio.create_task(TX.rx())
        if ID == "GCS":
            print("Detected as GCS")
            # GCS tasks, this is the handlers to pass received messages to the mavlink socket and catch messages to transmit
            asyncio.create_task(TX.self_RX())
            pass
        elif ID.__contains__("DR"):
            print("Detected as Drone")
            while not TX.getHandshakeStatus():
                await asyncio.sleep(0.001)  # block to prevent sending mav messages before they can be accepted
            # Drone tasks, this involves things like publishing the heartbeat and telemetry
            # Either the FC will provide messages as self timed intervals, or we request messages vai timed intervals on the
            # RPI
            #   Technically the second option could provide less overhead for the FC
            # If first option, we just sit and listen until a messages is given which is then sorted via some ID
            # If second option, the messages.heartbeat/GPS task will send a request to the FC and then packages returned
            # data

            # Mavlink tasks
            # messenger = messages.messages(vehicle)
            # conn = "/dev/ttyACM0"
            # FC = Serial_Connection(conn, messenger)

        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print("Cancelling")
        TX.end()
        resetWiFi()
        exit()
    # mav.gps_raw_int_send()
    # mav.attitude_send()


if __name__ == '__main__':
    try:
        print("Running")
        task = asyncio.run(main())
    except KeyboardInterrupt:
        print("Ending run")
        print("Goodbye")
# TODO: setup serial link with Arduino
# TODO:     establish standard drone telem messages to base station
