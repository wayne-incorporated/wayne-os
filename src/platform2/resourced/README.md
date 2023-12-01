# resourced - Chrome OS Resource Management Daemon

resourced supports the following 2 D-Bus interfaces for resource management.
Check go/resourced for details.

*   org.chromium.MemoryPressure - low memory notification API
    *   When memory pressure is high, notifying subsystems to free memory.
    *   Method GetAvailableMemoryKB - returns the available memory.
    *   Method GetMemoryMarginsKB - returns the margin (threshold) for critical
        and moderate memory pressure.

## ChromeOS Config

The following chromeos-config values are supported:

 * resource/
    * {ac,dc}
      * web-rtc-power-preferences/governor/
        * ondemand/
          * powersave-bias
      * fullscreen-power-preferences/governor/..
      * vm-boot-power-preferences/governor/..
      * borealis-gaming-power-preferences/governor/..
      * arcvm-gaming-power-preferences/governor/..
      * default-power-preferences/governor/..

## Debugging

You can use the following to call the dbus service:

```bash
$ dbus-send --print-reply --system --dest=org.chromium.ResourceManager /org/chromium/ResourceManager org.chromium.ResourceManager.SetRTCAudioActive byte:1
$ dbus-send --print-reply --system --dest=org.chromium.ResourceManager /org/chromium/ResourceManager org.chromium.ResourceManager.GetRTCAudioActive
```
