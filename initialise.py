import subprocess
import time


def b_to_string(arg):
    return "".join(map(chr, arg))


# Current ISSUES, renaming the wifi device seems to get overridden by the system as soon as it is done by the code
# Find a fix, or update adaptor name to the found name
def initialise_wifi(wifi_adaptor="wlan1"):
    # device_list = b_to_string(subprocess.check_output(["lsusb"])).split("\n")
    # wifi_device = ""
    # for device in device_list:
    #    if "RTL88" in device:
    #        wifi_device = device
    #        break

    # device_details = wifi_device.split("ID")[1].strip()[0:9]
    # deviceID, deviceAddr = device_details.split(":")
    # Reset the USB mode to ensure it is working
    # subprocess.check_output(['usb_modeswitch', '-v', '0x' + deviceID, '-p', '0x' + deviceAddr, '--reset-usb'])
    # time.sleep(1)
    # Reset the random name to predictable
    adapters = b_to_string(
        subprocess.check_output(["iwconfig"], stderr=subprocess.DEVNULL)
    ).split("\n\n")
    for adapter in adapters:
        if "WIFI@REALTEK" in adapter or "WIFI@RTL" in adapter:
            subprocess.check_output(
                ["ip", "link", "set", adapter.split(" ")[0], "name", "wlan1"]
            )
            break
    # now set the device to monitor mode and to use channel 36

    subprocess.check_output(["sudo", "ip", "link", "set", wifi_adaptor, "down"])
    time.sleep(0.3)
    subprocess.check_output(["sudo", "iw", wifi_adaptor, "set", "monitor", "none"])
    time.sleep(0.3)
    subprocess.check_output(["sudo", "ip", "link", "set", wifi_adaptor, "up"])
    time.sleep(0.3)
    subprocess.check_output(["sudo", "iw", wifi_adaptor, "set", "channel", "11"])
    time.sleep(1)
    return wifi_adaptor


def reset_wifi(wifi_adaptor="wlan1"):
    subprocess.check_output(["sudo", "ip", "link", "set", wifi_adaptor, "down"])
    time.sleep(0.3)
    subprocess.check_output(["sudo", "iw", wifi_adaptor, "set", "type", "managed"])
    time.sleep(0.3)
    subprocess.check_output(["sudo", "ip", "link", "set", wifi_adaptor, "up"])
    time.sleep(0.3)
