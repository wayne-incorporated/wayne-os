# pciguard: Chromeos security tool for external PCI devices

## ABOUT

pciguard is daemon that is listens to following events:
 - session events: such as user login / logoff and screen lock / unlock,
 - udev events: plugging in of new thunderbolt devices.
 - Chrome flag changes: for user permission flag changes.

These events change the security policies around external PCI devices. This
mostly concerns thunderbolt / USB4 peripherals that allow PCIe tunnels to be
established, but can also be used for any other technologies that allow external
PCI devices, e.g. SD Express cards.

In short, this daemon implements the security policy of allowing external PCIe
devices only when a user is signed in, and when user has opted for it using
the appropriate [chrome://flags](chrome://flags) setting.
See flag details [here](https://buganizer.corp.google.com/issues/172397647)
