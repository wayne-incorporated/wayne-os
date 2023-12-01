# Device Firmware Update (DFU) Notification Library

## Summary

The Device Firmware Update Notification Library provides APIs to be used by
device updaters to notify Chrome OS of the current state of the update as it
changes.

## How to use

Include the library package in the ebuild system and use the package config (pc)
file to set up the environment.

#include <libdfu_notification/dfu_log_notification.h>
...

DfuLogNotification notification;

notification.StartUpdate("MyCamera");
...
notification.UpdateProgress("MyCamera", 20);
...
notification.EndUpdate("MyCamera", true);
