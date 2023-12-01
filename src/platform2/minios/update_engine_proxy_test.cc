// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/update_engine_proxy.h"

#include <memory>

#include <base/test/mock_log.h>
#include <gmock/gmock-actions.h>
#include <gtest/gtest.h>
#include <update_engine/dbus-proxy-mocks.h>

#include "minios/utils.h"

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::WithArg;

namespace minios {

class UpdateEngineProxyTest : public ::testing::Test {
 public:
  void SetUp() override {
    // Setup a mock logger to ensure alert.
    mock_log_.StartCapturingLogs();
    // Ignore most log call, the tests below should expect any relevant calls.
    EXPECT_CALL(mock_log_, Log(_, _, _, _, _)).Times(testing::AnyNumber());
  }

 protected:
  base::test::MockLog mock_log_;
  std::unique_ptr<org::chromium::UpdateEngineInterfaceProxyMock>
      update_engine_proxy_interface_ =
          std::make_unique<org::chromium::UpdateEngineInterfaceProxyMock>();
};

TEST_F(UpdateEngineProxyTest, AlertOnRebootFailure) {
  // Force reboot to fail to cause an alert.
  EXPECT_CALL(*update_engine_proxy_interface_, RebootIfNeeded(_, _))
      .WillOnce(DoAll(WithArg<0>(Invoke([](brillo::ErrorPtr* error) {
                        // Set error message so that the proxy doesn't crash
                        // trying to read the code.
                        *error = brillo::Error::Create(FROM_HERE, "domain",
                                                       "code", "msg");
                      })),
                      Return(false)));
  UpdateEngineProxy update_engine_proxy{
      std::move(update_engine_proxy_interface_)};

  // Logger expectation.
  EXPECT_CALL(mock_log_,
              Log(::logging::LOGGING_ERROR, _, _, _,
                  testing::HasSubstr(AlertLogTag(kCategoryReboot).c_str())));
  update_engine_proxy.Reboot();
}

TEST_F(UpdateEngineProxyTest, AlertOnStartUpdateFailure) {
  // Force update to fail to cause an alert.
  EXPECT_CALL(*update_engine_proxy_interface_, Update(_, _, _))
      .WillOnce(DoAll(WithArg<1>(Invoke([](brillo::ErrorPtr* error) {
                        *error = brillo::Error::Create(FROM_HERE, "domain",
                                                       "code", "msg");
                      })),
                      Return(false)));
  UpdateEngineProxy update_engine_proxy{
      std::move(update_engine_proxy_interface_)};

  // Logger expectation.
  EXPECT_CALL(mock_log_,
              Log(::logging::LOGGING_ERROR, _, _, _,
                  testing::HasSubstr(AlertLogTag(kCategoryUpdate).c_str())));
  update_engine_proxy.StartUpdate();
}

}  // namespace minios
