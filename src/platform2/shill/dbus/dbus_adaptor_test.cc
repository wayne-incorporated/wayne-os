// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_adaptor.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/store/property_store_test.h"

namespace shill {

class DBusAdaptorTest : public PropertyStoreTest {
 public:
  DBusAdaptorTest() = default;

  ~DBusAdaptorTest() override = default;
};

TEST_F(DBusAdaptorTest, SanitizePathElement) {
  EXPECT_EQ("0Ab_y_Z_9_", DBusAdaptor::SanitizePathElement("0Ab/y:Z`9{"));
  EXPECT_EQ("aB_f_0_Y_z", DBusAdaptor::SanitizePathElement("aB-f/0@Y[z"));
}

}  // namespace shill
