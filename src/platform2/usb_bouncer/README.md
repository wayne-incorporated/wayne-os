# USB Bouncer

Tools for managing USBGuard allow-lists and configuration on Chrome OS

Particularly the following operations are supported:
* `cleanup`: removing old allow-list entries
* `genrules`: generate a rules.conf for usbguard and write it to stdout
* `udev`: update the allow-lists based on usb related udev events
* `userlogin`: copy entries for any connected devices from the global
    database to the user database.
