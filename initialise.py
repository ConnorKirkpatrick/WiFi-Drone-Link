import sys, subprocess, time


def bToString(arg):
    return ''.join(map(chr, arg))


# Current ISSUES, renaming the wifi device seems to get overridden by the system as soon as it is done by the code
# Find a fix, or update adaptor name to the found name
def initialiseWiFi(wifiAdaptor='wlan1'):
    deviceList = bToString(subprocess.check_output(['lsusb'])).split("\n")
    # wifiDevice = ""
    # for device in deviceList:
    #     if device.__contains__("RTL88"):
    #         wifiDevice = device
    #         break
    #
    # deviceDetails = wifiDevice.split("ID")[1].strip()[0:9]
    # deviceID, deviceAddr = deviceDetails.split(":")
    # # Reset the USB mode to ensure it is working
    # subprocess.check_output(['usb_modeswitch', '-v', '0x' + deviceID, '-p', '0x' + deviceAddr, '--reset-usb'])
    # # Reset the random name to predictable
    # adapters = bToString(subprocess.check_output(['iwconfig'], stderr=subprocess.DEVNULL)).split("\n\n")
    # for adapter in adapters:
    #     if adapter.__contains__("WIFI@REALTEK") or adapter.__contains__("WIFI@RTL"):
    #         subprocess.run(['ip', 'link', 'set', adapter.split(" ")[0], 'name', 'wlan1'])
    #         break
    # # now set the device to monitor mode and to use channel 36
    # print(subprocess.check_output(['ip', 'link', 'set', wifiAdaptor, 'down']))
    # time.sleep(0.3)
    # print(subprocess.check_output(['iw', wifiAdaptor, 'set', 'monitor', 'none']))
    # time.sleep(0.3)
    # print(subprocess.check_output(['ip', 'link', 'set', wifiAdaptor, 'up']))
    # time.sleep(0.3)
    # print(subprocess.check_output(['iw', 'dev', wifiAdaptor, 'set', 'channel', '36']))
