// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_TEST_UTIL_H_
#define POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_TEST_UTIL_H_

#include "power_manager/proto_bindings/backlight.pb.h"

#include <string>

namespace power_manager {

namespace system {
class DBusWrapperStub;
}

namespace policy::test {

// Helper methods used by unit tests to invoke various D-Bus methods exported by
// BacklightController implementations.
void CallIncreaseScreenBrightness(system::DBusWrapperStub* wrapper);
void CallDecreaseScreenBrightness(system::DBusWrapperStub* wrapper,
                                  bool allow_off);
void CallSetScreenBrightness(
    system::DBusWrapperStub* wrapper,
    double percent,
    SetBacklightBrightnessRequest_Transition transition,
    SetBacklightBrightnessRequest_Cause cause);

// Checks that the D-Bus signal at |index| has name |signal_name| and
// describes a brightness change to (rounded) |brightness_percent| for |cause|.
void CheckBrightnessChangedSignal(system::DBusWrapperStub* wrapper,
                                  size_t index,
                                  const std::string& signal_name,
                                  double brightness_percent,
                                  BacklightBrightnessChange_Cause cause);

// Return the most recent BacklightBrightnessChange signal.
//
// Returns a default proto and logs a test failure if not such signal
// has been sent.
BacklightBrightnessChange GetLastBrightnessChangedSignal(
    system::DBusWrapperStub* wrapper);

}  // namespace policy::test
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_TEST_UTIL_H_
