// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_DBUS_INTERFACE_H_
#define TRUNKS_DBUS_INTERFACE_H_

namespace trunks {

constexpr char kTrunksInterface[] = "org.chromium.Trunks";
constexpr char kTrunksServicePath[] = "/org/chromium/Trunks";
constexpr char kTrunksServiceName[] = "org.chromium.Trunks";

// Methods exported by trunks.
constexpr char kSendCommand[] = "SendCommand";

};  // namespace trunks

#endif  // TRUNKS_DBUS_INTERFACE_H_
