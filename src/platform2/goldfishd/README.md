# Goldfishd: Android Emulator Daemon

## About

Goldfishd (Android Emulator Daemon) is a daemon for getting messages sent from
the host when running Chrome OS inside the Android Emulator. Because the code
name of virtual hardware provided by Android Emulator is goldfish, we call it
Goldfishd. It's only available on test images for testing/development purposes.

## Work flow

This daemon opens /dev/goldfish_pipe to read messages from it. Messages from the
host trigger different actions inside Chrome OS. See goldfishd::message in
goldfish_library.h for all supported messages.
