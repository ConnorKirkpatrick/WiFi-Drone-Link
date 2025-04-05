import asyncio
import os

#from pymavlink.dialects.v20 import common as mavlink2
#from Communications.radio import Radio

from initialise import initialise_wifi, reset_wifi
#from Communications import message_store
from Drone.drone import Drone
from Drone.gcs import GCS

async def main():
    device = None
    try:
        print("Started")
        initialise_wifi()
        os.environ["MAVLINK20"] = "1"
        # read settings from file
        config = open("config.txt", "r", encoding="UTF-8")
        device_id = config.readline().split(":")[1].strip("\n")
        interface = config.readline().split(":")[1].strip("\n")
        channel = config.readline().split(":")[1].strip("\n")
        initial_port = config.readline().split(":")[1].strip("\n")
        config.close()

        # packet_outbox = message_store.MessageStore()
        # inputStream = multiprocessing.Queue()
        if device_id == "GCS":
            print("Detected as GCS")
            device = GCS("GCS", interface, channel, initial_port, True)
        elif "DR" in device_id:
            print("Detected as Drone")
            device = Drone(device_id, interface, channel, initial_port, True)


            # while not device_radio.get_handshake_status():
            #     # block to prevent sending mav messages before they can be
            #     # accepted
            #     await asyncio.sleep(0.001)









        # Note: file is the address/device mavlink will try to transmit on. We will route this to our
        # own structure to allow us to encrypt and broadcast the message

        # Global tasks, start these for both ground station and drone
        #   Radio Tasks
        #asyncio.create_task(device_radio.tx())
        #asyncio.create_task(device_radio.rx())

            # Drone tasks, this involves things like publishing the heartbeat and telemetry
            # Either the FC will provide messages as self timed intervals, or we request messages vai timed intervals
            # on the RPI
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
        device.stop()
        reset_wifi()


if __name__ == "__main__":
    try:
        print("Running")
        task = asyncio.run(main())
    except KeyboardInterrupt:
        print("Ending run")
        print("Goodbye")
