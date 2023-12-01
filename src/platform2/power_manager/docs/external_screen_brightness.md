# Chrome OS External Screen Brightness Behavior

The backlight brightness for external displays is controlled using DDC/CI.
Powerd only accepts requests to increase/decrease the external display's
brightness, not to set to an absolute brightness. If there is more than one
external display, the brightness is changed on all of them (assuming they all
implement DDC/CI).

Some Chromeboxes work with external displays that also contain an ambient light
sensor in the display bezel. Powerd can separately control the brightness of
these displays based on the ambient light level detected by the sensor in the
display. This feature is disabled by default but can be enabled with the
`external-ambient-light-sensor` preference. It can also be dynamically
enabled/disabled via DBus with `SetExternalDisplayALSBrightness`.

For external displays with ambient light sensors, the brightness levels used are
controlled by the `external-backlight-als-steps` preference. The default levels
used set the brightness very low in low light conditions, and to full brightness
otherwise.

For boards that support external displays with ambient light sensors, if
automatic brightness control has been disabled, an exception is made to allow
setting an absolute brightness to external displays with ambient light sensors.
This does not apply to external displays without an ambient light sensor.
