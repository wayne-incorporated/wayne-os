// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_DBUS_BUS_H_
#define TRUNKS_MOCK_DBUS_BUS_H_

#include <string>

#include <dbus/bus.h>
#include <gmock/gmock.h>

namespace trunks {

class MockDBusBus : public dbus::Bus {
 public:
  MockDBusBus() : dbus::Bus(dbus::Bus::Options()) {}

  MOCK_METHOD0(Connect, bool());
  MOCK_METHOD0(ShutdownAndBlock, void());
  MOCK_METHOD2(GetServiceOwnerAndBlock,
               std::string(const std::string&,
                           dbus::Bus::GetServiceOwnerOption));
  MOCK_METHOD2(GetObjectProxy,
               dbus::ObjectProxy*(const std::string&, const dbus::ObjectPath&));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_DBUS_BUS_H_
