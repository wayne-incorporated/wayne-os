// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_DBUS_INTERFACE_H_
#define VTPM_DBUS_INTERFACE_H_

namespace vtpm {

constexpr char kVtpmInterface[] = "org.chromium.Vtpm";
constexpr char kVtpmServicePath[] = "/org/chromium/Vtpm";
constexpr char kVtpmServiceName[] = "org.chromium.Vtpm";

// Methods exported by vtpm.
constexpr char kSendCommand[] = "SendCommand";

}  // namespace vtpm

#endif  // VTPM_DBUS_INTERFACE_H_
