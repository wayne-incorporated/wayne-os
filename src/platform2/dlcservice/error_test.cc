// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/errors/error_codes.h>
#include <dbus/dlcservice/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "dlcservice/error.h"

using brillo::errors::dbus::kDomain;

namespace dlcservice {

TEST(Error, Create) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "error-code", "msg");
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_STREQ("error-code", err->GetCode().c_str());
  EXPECT_STREQ("msg", err->GetMessage().c_str());
}

TEST(Error, CreateInternal) {
  brillo::ErrorPtr err = Error::CreateInternal(FROM_HERE, "error-code", "msg");
  EXPECT_STREQ(kDlcErrorDomain, err->GetDomain().c_str());
  EXPECT_STREQ("error-code", err->GetCode().c_str());
  EXPECT_STREQ("msg", err->GetMessage().c_str());
}

TEST(Error, ToString) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "error-code", "message");
  EXPECT_STREQ("Error Code=error-code, Error Message=message",
               Error::ToString(err).c_str());
}

TEST(Error, AddTo) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "root-code", "msg");
  Error::AddTo(&err, FROM_HERE, "linked-code", "msg-linked");
  EXPECT_STREQ("linked-code", err->GetCode().c_str());
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_STREQ("root-code", err->GetInnerError()->GetCode().c_str());
}

TEST(Error, AddInternalTo) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "root-code", "msg");
  Error::AddInternalTo(&err, FROM_HERE, "linked-code", "msg-linked");
  EXPECT_STREQ("linked-code", err->GetCode().c_str());
  EXPECT_STREQ(kDlcErrorDomain, err->GetDomain().c_str());
  EXPECT_STREQ("root-code", err->GetInnerError()->GetCode().c_str());
}

TEST(Error, GetRootErrorCode) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "root-code", "msg");
  Error::AddInternalTo(&err, FROM_HERE, "linked-code", "msg-linked");
  Error::AddInternalTo(&err, FROM_HERE, "linked-code2", "msg-linked");
  EXPECT_STREQ("root-code", Error::GetRootErrorCode(err).c_str());
}

TEST(Error, GetErrorCodeInternalBase) {
  brillo::ErrorPtr err = Error::CreateInternal(FROM_HERE, "root-code", "msg");
  Error::AddTo(&err, FROM_HERE, kErrorBusy, "dbus-msg-linked");
  Error::AddInternalTo(&err, FROM_HERE, "linked-code2", "msg-linked");
  Error::AddTo(&err, FROM_HERE, "linked-code2", "dbus-msg-linked");
  EXPECT_STREQ(kErrorBusy, Error::GetErrorCode(err).c_str());
}

TEST(Error, GetErrorCodeDbusBase) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "root-code", "msg");
  Error::AddTo(&err, FROM_HERE, kErrorBusy, "dbus-msg-linked");
  Error::AddInternalTo(&err, FROM_HERE, "linked-code2", "msg-linked");
  Error::AddTo(&err, FROM_HERE, "linked-code2", "dbus-msg-linked");
  EXPECT_STREQ(kErrorBusy, Error::GetErrorCode(err).c_str());
}

TEST(Error, ConvertToDbusError_internal_dbus) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "dbus-code", "msg");
  Error::AddInternalTo(&err, FROM_HERE, "internal-code", "msg-linked");
  EXPECT_STREQ("internal-code", err->GetCode().c_str());
  EXPECT_STREQ(kDlcErrorDomain, err->GetDomain().c_str());
  EXPECT_TRUE(err->GetInnerError() != nullptr);

  Error::ConvertToDbusError(&err);
  EXPECT_STREQ("dbus-code", err->GetCode().c_str());
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_TRUE(err->GetInnerError() == nullptr);
}

TEST(Error, ConvertToDbusError_dbus) {
  brillo::ErrorPtr err = Error::Create(FROM_HERE, "dbus-code", "msg");
  Error::ConvertToDbusError(&err);
  EXPECT_STREQ("dbus-code", err->GetCode().c_str());
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_TRUE(err->GetInnerError() == nullptr);
}

TEST(Error, ConvertToDbusError_dbus_internal) {
  brillo::ErrorPtr err =
      Error::CreateInternal(FROM_HERE, "internal-code", "msg");
  Error::AddTo(&err, FROM_HERE, "dbus-code", "msg-linked");
  EXPECT_STREQ("dbus-code", err->GetCode().c_str());
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_TRUE(err->GetInnerError() != nullptr);

  Error::ConvertToDbusError(&err);
  EXPECT_STREQ("dbus-code", err->GetCode().c_str());
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_TRUE(err->GetInnerError() == nullptr);
}

TEST(Error, ConvertToDbusError_internal_only) {
  brillo::ErrorPtr err =
      Error::CreateInternal(FROM_HERE, "internal-code", "msg");
  Error::AddInternalTo(&err, FROM_HERE, "internal-code2", "msg-linked");

  Error::ConvertToDbusError(&err);
  EXPECT_STREQ(kErrorInternal, err->GetCode().c_str());
  EXPECT_STREQ(kDomain, err->GetDomain().c_str());
  EXPECT_TRUE(err->GetInnerError() == nullptr);
}

}  // namespace dlcservice
