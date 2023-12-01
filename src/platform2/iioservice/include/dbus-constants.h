// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_INCLUDE_DBUS_CONSTANTS_H_
#define IIOSERVICE_INCLUDE_DBUS_CONSTANTS_H_

namespace iioservice {

constexpr char kIioserviceServiceName[] = "org.chromium.Iioservice";
constexpr char kIioserviceServicePath[] = "/org/chromium/Iioservice";
constexpr char kIioserviceInterface[] = "org.chromium.Iioservice";
// Methods
constexpr char kMemsSetupDoneMethod[] = "MemsSetupDone";
constexpr char kMemsRemoveDoneMethod[] = "MemsRemoveDone";

}  // namespace iioservice

#endif  // IIOSERVICE_INCLUDE_DBUS_CONSTANTS_H_
