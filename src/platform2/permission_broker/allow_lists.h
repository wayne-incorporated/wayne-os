// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_ALLOW_LISTS_H_
#define PERMISSION_BROKER_ALLOW_LISTS_H_

using policy::DevicePolicy;

namespace permission_broker {

// The Arduino vendor IDs are derived from https://raw.githubusercontent.com
// /arduino/ArduinoCore-avr/master/boards.txt
// /arduino/ArduinoCore-sam/master/boards.txt
// /arduino/ArduinoCore-samd/master/boards.txt
// using
// grep -o -E  "vid\..*=(0x.*)" *boards.txt | sed "s/vid\..=//g" | sort -f | \
// uniq -i
const DevicePolicy::UsbDeviceId kSerialAllowedIds[] = {
    {0x03eb, 0x2145},  // Arduino Uno WiFi Rev2 (ATmega4809)
    {0x0525, 0xa4a7},  // Linux-USB Serial Gadget (CDC ACM mode)
    {0x067b, 0x2323},  // Prolific Technology USB-Serial Controller
    {0x093c, 0x1101},  // Intrepid Control Systems ValueCAN 4
    {0x0d28, 0x0204},  // BBC micro:bit
    {0x1a86, 0x55d3},  // QinHeng Electronics USB Single Serial
    {0x1a86, 0x55d4},  // QinHeng Electronics USB Single Serial
    {0x2341, 0},       // Arduino
    {0x1b4f, 0},       // Sparkfun
    {0x239a, 0},       // Adafruit
    {0x2a03, 0},       // doghunter.org
    {0x10c4, 0},       // Silicon Labs
    {0x2c99, 0},       // Prusa Research
    {0x2e8a, 0},       // Raspberry Pi
    {0x18d1, 0x4f00},  // Google Pixel ROM recovery
    {0x18d1, 0x5002},  // Google Servo V2
    {0x18d1, 0x5003},  // Google Servo V2
    {0x18d1, 0x500a},  // Google twinkie
    {0x18d1, 0x500b},  // Google Plankton
    {0x18d1, 0x500c},  // Google Plankton
    {0x18d1, 0x5014},  // Google Cr50
    {0x18d1, 0x501a},  // Google Servo micro
    {0x18d1, 0x501b},  // Google Servo V4
    {0x18d1, 0x501f},  // Google Suzyq
    {0x18d1, 0x5020},  // Google Sweetberry
    {0x18d1, 0x5027},  // Google Tigertail
    {0x18d1, 0x5036},  // Google Chocodile
    {0x18d1, 0x504a},  // Google Ti50
    {0x18d1, 0x520D},  // Google Servo V4p1
    {0x18d1, 0x5213},  // Google Twinkie V2
    {0x1d50, 0x6140},  // QuickLogic QuickFeather evaluation board bootloader
    {0x1d50, 0x6130},  // TinyFPGA BX Bootloader old openmoko VID:PID
    {0x1d50, 0x614e},  // OpenMoko, Inc. Klipper
    {0x1209, 0x2100},  // TinyFPGA BX Bootloader new pid.codes VID:PID
    {0x1209, 0x5bf0},  // Arty FPGA board
};

const DevicePolicy::UsbDeviceId kHIDAllowedIds[] = {
    {0x2e73, 0x0001},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0002},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0003},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0004},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0005},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0006},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0007},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0008},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0009},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0010},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0011},  // BackyardBrains Neuron SpikerBox
    {0x2e73, 0x0012},  // BackyardBrains Neuron SpikerBox
};

const DevicePolicy::UsbDeviceId kFixedAllowedIds[] = {
    {0x0c27, 0x3bfa},  // USB card reader
    {0x0554, 0x1001},  // Nuance PowerMic III
    {0xdf04, 0x0004},  // Nuance PowerMic III
};

const DevicePolicy::UsbDeviceId kWebHIDAllowedIds[] = {
    {0x0c27, 0x3bfa},  // rf IDEAS reader
    {0x0c27, 0x3b1e},  // rf IDEAS reader
    {0x0c27, 0xccda},  // rf IDEAS reader
    {0x0c27, 0xccdb},  // rf IDEAS reader
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_ALLOW_LISTS_H_
