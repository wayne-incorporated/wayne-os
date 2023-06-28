# Known (ongoing) Issues

## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).

## HW compatibility
We (Wayne Inc.) modify kernel, update device drivers and firmwares from upstream Chromium OS, however the HW compatibility is not as compatible as MS Windows since Linux/Chromium-OS kernel/firmware doesn't support some devices perfectly and we also face difficulties to test a lot of devices. 
<br>We apologize to users about this issue and we will try our best to improve this.
#### Symptom
- Cannot find Wi-Fi, or cannot connect to Wi-Fi: common Wireless LAN issue
- Cannot see the initial setup screen in booting process, but can switch to console mode: GPU issue in high probability
#### Solution
- If you are an optimist, report working/non-working device model to [hw_compatibility_information.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/release/hw_compatibility_information.md) or [community](https://www.facebook.com/groups/wayneosgroup), then relax and wait until it is fixed in Wayne OS or upstream Chromium OS
- Or plug in a [wireless LAN adapter](https://www.google.com/search?q=wireless+LAN+adapter&newwindow=1&sxsrf=ALeKk03aOfT-WximunZ5xF7ooFsttcmLjQ%3A1628912656397&ei=EDwXYbPKF7HcmAWPkJawCg&oq=wireless+LAN+adapter&gs_lcp=Cgdnd3Mtd2l6EAMyBAgjECcyBggAEAcQHjIGCAAQBxAeMgUIABCABDIFCAAQgAQyBQgAEIAEMgUIABCABDIFCAAQgAQyBQgAEIAEMgUIABCABDoHCCMQsAMQJzoHCAAQRxCwAzoHCAAQsAMQQzoHCCMQsAIQJ0oECEEYAFCCHFjAJmCcQWgBcAJ4AIABhgGIAeUGkgEDMC43mAEAoAEByAEKwAEB&sclient=gws-wiz&ved=0ahUKEwizkoTCzK_yAhUxLqYKHQ-IBaYQ4dUDCA4&uact=5) that works or exists in [hw_compatibility_information.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/release/hw_compatibility_information.md) list on the PC (Some of our customers are actually using this solution on the industry field)


## Ethernet with static IP
If ethernet (LAN) cable is connected, OS expects [DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) IP automatically.
<br>However if you use static IP, you have to configure it manually.
#### Symptom
Ethernet with static IP is not working, despite manual static IP configuration in GUI.
#### Solution
After static IP configuration, plug off the ethernet cable, then connect it again.

## USB flash drive's quality
A USB flash drive (or a removable flash disk) consists of [Flash memory](https://en.wikipedia.org/wiki/Flash_memory) and [Controller](https://en.wikipedia.org/wiki/Flash_memory_controller) like SSD,
However many USB flash drives Flash memory and Controller performance/quality is worse than SSD due to their original purpose is to store temporary files, so the product cost is cheaper than SSD.
#### Symptom
- Read/write corruption (failure of OS installation to a USB flash drive or a local disk in PC)
- Lag of OS
- A USB flash drive becomes hotter than the others
- 5-10% of *Kingston DT50* models got this issue (over 100 USB flash drives are tested).

#### Solution
Select a decent USB flash drive (with nice controller or SLC/MLC flash memory or fast read/write speed) to use OS on it.

## Wi-Fi interference
[Logitech Unifying for Chrome](https://chrome.google.com/webstore/detail/logitech-unifying-for-chr/agpmgihmmmfkbhckmciedmhincdggomo?hl=en) extension might cause Wi-Fi doesn't work in OS.


# Solved Issues

## Screen freeze in booting process
This bug has been solved since wayne-os-3q21-r1 version.
#### Symptom
Cannot see initial screen in booting process or after PC installation.
#### Solution
- Try to press _Enter_ key
- Try to switch to console mode then comeback to GUI mode again. Refer [using_shell.md](https://gitlab.com/wayne-inc/wayneos/-/blob/master/docs/en/how-to/using_shell.md).
