import sys, subprocess


def bToString(arg):
    return ''.join(map(chr, arg))


def initialiseWiFi(wifiAdaptor='wlan1'):
    deviceList = bToString(subprocess.check_output(['lsusb'])).split("\n")
    wifiDevice = ""
    for device in deviceList:
        if device.__contains__("RTL88"):
            wifiDevice = device
            break

    deviceDetails = wifiDevice.split("ID")[1].strip()[0:9]
    deviceID, deviceAddr = deviceDetails.split(":")
    # Reset the USB mode to ensure it is working
    subprocess.check_output(['sudo', 'usb_modeswitch', '-v', '0x' + deviceID, '-p', '0x' + deviceAddr, '--reset-usb'])
    # Reset the random name to predictable
    adapters = bToString(subprocess.check_output(['iwconfig'], stderr=subprocess.DEVNULL)).split("\n\n")
    for adapter in adapters:
        if adapter.__contains__("WIFI@REALTEK"):
            subprocess.run(['sudo', 'ip', 'link', 'set', adapter.split(" ")[0], 'name', 'wlan1'])
            break
    # now set the device to monitor mode and to use channel 36
    subprocess.check_output(['sudo', 'iw', 'dev', wifiAdaptor, 'set', 'type', 'monitor'])
    subprocess.check_output(['sudo', 'ip', 'link', 'set', wifiAdaptor, 'up'])
    subprocess.check_output(['sudo', 'iw', 'dev', wifiAdaptor, 'set', 'channel', '36'])
