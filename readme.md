This project aims to create a wireless broadcast data-link between two systems using commercial off the shelf (COTS) hardware to avoid the high cost and legal issues around long-range radio devices<br>
This work aims to emulate the data link of open-HD and WFB-NG for a custom autopilot system, however will provide a more generic and accessible system<br>
Initially this is aimed top plug into a custom ground control system, in the future qgroundcontrol compatibility will be supported

TODO<br>
* Add general message structure
  * Received messages are decode and passed to another thread/async process to handle
  * Generated messages are encoded and passed to another thread/async process to forward
* Implement mavlink messages
* establish messaging protocols consistent with mavlink standards
* establish a configuration file for settings such as channel and address
* separation of message responsibility between the ground system and this app
* work out serialization for mavlink packet

Useful links:
Drive link: https://github.com/morrownr/8812au-20210629
