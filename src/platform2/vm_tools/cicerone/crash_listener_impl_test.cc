// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <map>
#include <string>

#include "vm_tools/cicerone/crash_listener_impl.h"
#include "vm_tools/cicerone/service.h"
#include "vm_tools/cicerone/service_testing_helper.h"

using ::testing::_;

namespace vm_tools {
namespace cicerone {

namespace {

class CrashListenerImplTest : public ::testing::Test {
 public:
  class CrashListenerMock : public CrashListenerImpl {
   public:
    explicit CrashListenerMock(
        base::WeakPtr<vm_tools::cicerone::Service> service)
        : CrashListenerImpl(service) {}
    MOCK_METHOD(std::string, GetLsbReleaseValue, (std::string), ());
  };
};

}  // namespace

TEST_F(CrashListenerImplTest, CorrectMetadataChanged) {
  ServiceTestingHelper test_framework(ServiceTestingHelper::NORMAL_MOCKS);
  test_framework.SetUpDefaultVmAndContainer();
  test_framework.ExpectNoDBusMessages();
  grpc::ServerContext ctx;
  CrashListenerMock crash_listener =
      CrashListenerMock(test_framework.get_service().GetWeakPtrForTesting());

  // Arrange
  ON_CALL(crash_listener, GetLsbReleaseValue("CHROMEOS_RELEASE_TRACK"))
      .WillByDefault(testing::Return("testimage-channel"));
  ON_CALL(crash_listener, GetLsbReleaseValue("CHROMEOS_RELEASE_DESCRIPTION"))
      .WillByDefault(testing::Return(
          "15309.0.0 (Test Build - root) developer-build volteer"));
  ON_CALL(crash_listener,
          GetLsbReleaseValue("CHROMEOS_RELEASE_CHROME_MILESTONE"))
      .WillByDefault(testing::Return("111"));
  CrashReport cr;
  google::protobuf::Map<std::string, std::string>& metadata =
      *cr.mutable_metadata();
  metadata["foo"] = "bar";
  metadata["upload_var_channel"] = "";
  metadata["upload_car_cros_milestone"] = "dev";

  // Act
  google::protobuf::Map<std::string, std::string> modified_md =
      crash_listener.ModifyCrashReport(&cr).metadata();

  // Assert
  EXPECT_EQ(modified_md["upload_var_lsb-release"],
            "15309.0.0 (Test Build - root) developer-build volteer");
  EXPECT_EQ(modified_md["upload_var_cros_milestone"], "111");
  EXPECT_EQ(modified_md["upload_var_channel"], "test");
}

}  // namespace cicerone
}  // namespace vm_tools
