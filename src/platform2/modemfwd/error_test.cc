// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/errors/error_codes.h>
#include <dbus/modemfwd/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "modemfwd/error.h"

namespace modemfwd {

TEST(Error, Create) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "error-code", "msg");
  EXPECT_STREQ(kModemfwdErrorDomain, err->GetDomain().c_str());
  EXPECT_STREQ("error-code", err->GetCode().c_str());
  EXPECT_STREQ("msg", err->GetMessage().c_str());
}

TEST(Error, CreateFromDbusError) {
  brillo::Error* dbus_err1 = nullptr;
  brillo::ErrorPtr err = Error::CreateFromDbusError(dbus_err1);
  EXPECT_STREQ(kModemfwdErrorDomain, err->GetDomain().c_str());
  EXPECT_STREQ("", err->GetCode().c_str());
  EXPECT_STREQ("", err->GetMessage().c_str());

  brillo::ErrorPtr dbus_err2 =
      brillo::Error::Create(FROM_HERE, "dbus", "error-code", "msg");
  err = Error::CreateFromDbusError(dbus_err2.get());
  EXPECT_STREQ("dbus", err->GetDomain().c_str());
  EXPECT_STREQ("error-code", err->GetCode().c_str());
  EXPECT_STREQ("msg", err->GetMessage().c_str());
}

}  // namespace modemfwd
