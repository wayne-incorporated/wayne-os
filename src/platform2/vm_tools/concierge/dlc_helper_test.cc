// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/dlc_helper.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <utility>

#include "base/memory/scoped_refptr.h"
#include "dlcservice/proto_bindings/dlcservice.pb.h"
#include "dlcservice/dbus-proxy-mocks.h"  //NOLINT (build/include_alpha)

using ::testing::_;

namespace vm_tools {
namespace concierge {
namespace {

class DlcHelperTest : public testing::Test {
 protected:
  using MockHandlePtr =
      std::unique_ptr<org::chromium::DlcServiceInterfaceProxyMock>;

  MockHandlePtr GetMockHandle() {
    return std::make_unique<org::chromium::DlcServiceInterfaceProxyMock>();
  }
};

TEST_F(DlcHelperTest, FailureImpliesNulloptAndError) {
  MockHandlePtr handle = GetMockHandle();
  EXPECT_CALL(*handle, GetDlcState(_, _, _, _))
      .WillOnce(testing::Invoke(
          [](const std::string& in_id, dlcservice::DlcState* out_state,
             brillo::ErrorPtr* error,
             int /*timeout_ms*/) -> bool { return false; }));

  DlcHelper helper(std::move(handle));
  std::string error;

  EXPECT_TRUE(error.empty());
  EXPECT_FALSE(helper.GetRootPath("foobar", &error).has_value());
  EXPECT_FALSE(error.empty());
}

TEST_F(DlcHelperTest, NotInstalledImpliesNulloptAndError) {
  MockHandlePtr handle = GetMockHandle();
  EXPECT_CALL(*handle, GetDlcState(_, _, _, _))
      .WillOnce(testing::Invoke(
          [](const std::string& in_id, dlcservice::DlcState* out_state,
             brillo::ErrorPtr* error, int /*timeout_ms*/) -> bool {
            out_state->set_state(dlcservice::DlcState_State_INSTALLING);
            return true;
          }));

  DlcHelper helper(std::move(handle));
  std::string error;

  EXPECT_TRUE(error.empty());
  EXPECT_FALSE(helper.GetRootPath("foobar", &error).has_value());
  EXPECT_FALSE(error.empty());
}

TEST_F(DlcHelperTest, InstalledReturnsRootPath) {
  MockHandlePtr handle = GetMockHandle();
  EXPECT_CALL(*handle, GetDlcState(_, _, _, _))
      .WillOnce(testing::Invoke(
          [](const std::string& in_id, dlcservice::DlcState* out_state,
             brillo::ErrorPtr* error, int /*timeout_ms*/) -> bool {
            EXPECT_EQ(in_id, "foobar");
            out_state->set_state(dlcservice::DlcState_State_INSTALLED);
            out_state->set_root_path("/path/to/dlc/root");
            return true;
          }));

  DlcHelper helper(std::move(handle));
  std::string error;
  std::optional<std::string> root_path = helper.GetRootPath("foobar", &error);

  EXPECT_TRUE(error.empty());
  EXPECT_TRUE(root_path.has_value());
  EXPECT_EQ(root_path.value(), "/path/to/dlc/root");
}

}  // namespace
}  // namespace concierge
}  // namespace vm_tools
