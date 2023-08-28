## Note
This document is looking foward to your contribution (documentation, translation, reporting, suggestion, coding).
<br>TO-DO: This document requires contributions about useful Chromium flags.
<br>The features in this document have not been released yet. (2022-03-17)
 
## Accessing to chrome_dev.conf
- [login to console mode](https://github.com/wayne-incorporated/wayne-os/blob/main/docs/en/how-to/using_shell.md).
- Type command `/usr/sbin/mode_change-wayneos` (requires sudo pw).
- Reboot OS after modify the _chrome_dev.conf_.

#### Switching on flag:
1. Select flags in the _chrome_dev.conf_. 
2. Delete the sharp (#) which is ahead of the flag (Don't remove the sharp which is ahead of the explanation).
3. Add an argument, if the flag requires it.
#### Switching off flag:
1. Write a sharp mark (#) ahead of the flag.

## Useful flag set
#### For kiosk
- --kiosk: UI will be locked except web browser.
- --start-fullscreen: Web browser will be opened with full screen.
- --enable-virtual-keyboard: For touch screen.
#### For public PC
- --incognito: Web browser will be started with incognito mode.
