// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_CONSTANTS_H_

namespace diagnostics {

// Put the common and important message here to make it clear for our clients.

// Common status message of all Bluetooth routines.
inline constexpr char kBluetoothRoutineRunningMessage[] =
    "Bluetooth routine running.";
inline constexpr char kBluetoothRoutinePassedMessage[] =
    "Bluetooth routine passed.";

// Common failure message of all Bluetooth routines.
inline constexpr char kBluetoothRoutineFailedDiscoveryMode[] =
    "Bluetooth routine is not supported when adapter is in discovery mode.";

// Common error message of all Bluetooth routines.
inline constexpr char kBluetoothRoutineFailedGetAdapter[] =
    "Bluetooth routine failed to get main adapter.";
inline constexpr char kBluetoothRoutineFailedChangePowered[] =
    "Bluetooth routine failed to change adapter powered status.";
inline constexpr char kBluetoothRoutineFailedSwitchDiscovery[] =
    "Bluetooth routine failed to switch adapter discovery mode.";
inline constexpr char kBluetoothRoutineUnexpectedFlow[] =
    "Unexpected Bluetooth diagnostic flow.";

// Failure message of Bluetooth power routine.
inline constexpr char kBluetoothRoutineFailedVerifyPowered[] =
    "Bluetooth routine failed to verify adapter powered status.";

// Failure message of Bluetooth discovery routine.
inline constexpr char kBluetoothRoutineFailedVerifyDiscovering[] =
    "Bluetooth routine failed to verify adapter discovering status.";

// Failure message of Bluetooth pairing routine.
inline constexpr char kBluetoothRoutineFailedFindTargetPeripheral[] =
    "Bluetooth routine failed to find the device with peripheral ID.";
inline constexpr char kBluetoothRoutineFailedCreateBasebandConnection[] =
    "Bluetooth routine failed to create baseband connection.";
inline constexpr char kBluetoothRoutineFailedFinishPairing[] =
    "Bluetooth routine failed to finish pairing.";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BLUETOOTH_BLUETOOTH_CONSTANTS_H_
