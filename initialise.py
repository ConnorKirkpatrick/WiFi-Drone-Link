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

    subprocess.check_output(['sudo', 'usb_modeswitch', '-v', '0x' + deviceID, '-p', '0x' + deviceAddr, '--reset-usb'])
    # now set the device to monitor mode and to use channel 36
    subprocess.check_output(['sudo', 'iw', 'dev', wifiAdaptor, 'set', 'type', 'monitor'])
    subprocess.check_output(['sudo', 'ip', 'link', 'set', wifiAdaptor, 'up'])
    subprocess.check_output(['sudo', 'iw', 'dev', wifiAdaptor, 'set', 'channel', '36'])
