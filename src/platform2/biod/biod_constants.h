// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_CONSTANTS_H_
#define BIOD_BIOD_CONSTANTS_H_

namespace biod {

namespace dbus_constants {
// dbus::ObjectProxy::TIMEOUT_USE_DEFAULT value is -1 which informs DBus daemon
// that it should wait default amount of time for the daemon (25 seconds).
// Nevertheless we will define it here, so we can use it for calculations and
// protect from changes in DBus daemon. This value is used in many places across
// the biod, so please be careful when changing this. This is also used as upper
// bound in SendSessionRetrievePrimarySessionDuration(), please follow the
// comment in the function when changing this!
inline constexpr int kDbusTimeoutMs = 25000;

}  // namespace dbus_constants
}  // namespace biod

#endif  // BIOD_BIOD_CONSTANTS_H_
