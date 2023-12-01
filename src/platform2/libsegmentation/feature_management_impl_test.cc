// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libsegmentation/device_info.pb.h"
#include "libsegmentation/feature_management.h"
#include "libsegmentation/feature_management_impl.h"
#include "libsegmentation/feature_management_interface.h"
#include "libsegmentation/feature_management_util.h"

#include "proto/feature_management.pb.h"

namespace segmentation {

using chromiumos::feature_management::api::software::Feature;
using ::testing::Return;

// Use made up feature file:
const char* test_proto =
    "CiQKBUJhc2ljEhQKEmd3ZW5kYWxAZ29vZ2xlLmNvbSICAAEqAQAKHAoBRRIPCg1nZ0Bnb29nbG"
    "UuY29tGAIiAQEqAQEKHgoBRBIPCg1nZ0Bnb29nbGUuY29tGAIiAQEqAwABAgodCgFDEg8KDWdn"
    "QGdvb2dsZS5jb20YASIBASoCAQAKHAoBQhIPCg1nZ0Bnb29nbGUuY29tGAEiAQEqAQEKGwoBQR"
    "IPCg1nZ0Bnb29nbGUuY29tIgIAASoBAg==";

/*
  It produce the following bundle.
  Command line:
     echo "..." base64 -d | protoc -I "src/platform/feature-management/proto" \
            --decode=chromiumos.feature_management.api.software.FeatureBundle \
            src/platform/feature-management/proto/feature-management.proto
features {
  name: "Basic"
  contacts {
    email: "gwendal@google.com"
  }
  scopes: SCOPE_DEVICES_0
  scopes: SCOPE_DEVICES_1
  usages: USAGE_LOCAL
}
features {
  name: "E"
  contacts {
    email: "gg@google.com"
  }
  feature_level: 2
  scopes: SCOPE_DEVICES_1
  usages: USAGE_CHROME
}
features {
  name: "D"
  contacts {
    email: "gg@google.com"
  }
  feature_level: 2
  scopes: SCOPE_DEVICES_1
  usages: USAGE_LOCAL
  usages: USAGE_CHROME
  usages: USAGE_ANDROID
}
features {
  name: "C"
  contacts {
    email: "gg@google.com"
  }
  feature_level: 1
  scopes: SCOPE_DEVICES_1
  usages: USAGE_CHROME
  usages: USAGE_LOCAL
}
features {
  name: "B"
  contacts {
    email: "gg@google.com"
  }
  feature_level: 1
  scopes: SCOPE_DEVICES_1
  usages: USAGE_CHROME
}
features {
  name: "A"
  contacts {
    email: "gg@google.com"
  }
  feature_level: 0
  scopes: SCOPE_DEVICES_0
  scopes: SCOPE_DEVICES_1
  usages: USAGE_ANDROID
}
*/

// Test fixture for testing feature management.
class FeatureManagementImplTest : public ::testing::Test {
 public:
  FeatureManagementImplTest() = default;
  ~FeatureManagementImplTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    device_info_path_ = temp_dir_.GetPath().Append("device_info");
    auto fake =
        std::make_unique<FeatureManagementImpl>(device_info_path_, test_proto);
    feature_management_ = std::make_unique<FeatureManagement>(std::move(fake));
  }

 protected:
  // Directory and file path used for simulating device info data.
  base::ScopedTempDir temp_dir_;

  // File path where device info data will be simulated.
  base::FilePath device_info_path_;

  // Object to test.
  std::unique_ptr<FeatureManagement> feature_management_;
};

TEST_F(FeatureManagementImplTest, GetBasicFeature) {
  // Test with an empty file. Expect feature level to be 0, scope to 0.
  EXPECT_EQ(feature_management_->IsFeatureEnabled("A"), false);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementA"), true);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementAPad"),
            false);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementB"), false);

  std::set<std::string> features =
      feature_management_->ListFeatures(USAGE_ANDROID);
  EXPECT_EQ(features.size(), 1);
  EXPECT_NE(features.find("FeatureManagementA"), features.end());

  features = feature_management_->ListFeatures(USAGE_CHROME);
  EXPECT_EQ(features.size(), 0);
}

#if USE_FEATURE_MANAGEMENT
// Use database produced by chromeos-base/feature-management-data.
TEST_F(FeatureManagementImplTest, GetAndCacheStatefulFeatureLevelTest) {
  libsegmentation::DeviceInfo device_info;
  device_info.set_feature_level(libsegmentation::DeviceInfo_FeatureLevel::
                                    DeviceInfo_FeatureLevel_FEATURE_LEVEL_1);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));
  EXPECT_EQ(
      feature_management_->GetFeatureLevel(),
      FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_1 -
          FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_VALID_OFFSET);

  // Even though the file is changed we should still get the cached value stored
  // from the previous attempt.
  device_info.set_feature_level(libsegmentation::DeviceInfo_FeatureLevel::
                                    DeviceInfo_FeatureLevel_FEATURE_LEVEL_0);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));
  EXPECT_EQ(
      feature_management_->GetFeatureLevel(),
      FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_1 -
          FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_VALID_OFFSET);
}

// Use database produced by chromeos-base/feature-management-data.
TEST_F(FeatureManagementImplTest, GetAndCacheStatefulScopeLevelTest) {
  libsegmentation::DeviceInfo device_info;
  device_info.set_scope_level(libsegmentation::DeviceInfo_ScopeLevel::
                                  DeviceInfo_ScopeLevel_SCOPE_LEVEL_1);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));
  EXPECT_EQ(
      feature_management_->GetScopeLevel(),
      FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_1 -
          FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_VALID_OFFSET);

  // Even though the file is changed we should still get the cached value stored
  // from the previous attempt.
  device_info.set_scope_level(libsegmentation::DeviceInfo_ScopeLevel::
                                  DeviceInfo_ScopeLevel_SCOPE_LEVEL_0);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));
  EXPECT_EQ(
      feature_management_->GetScopeLevel(),
      FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_1 -
          FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_VALID_OFFSET);
}

TEST_F(FeatureManagementImplTest, GetFeatureLevel0) {
  libsegmentation::DeviceInfo device_info;
  device_info.set_feature_level(libsegmentation::DeviceInfo_FeatureLevel::
                                    DeviceInfo_FeatureLevel_FEATURE_LEVEL_0);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));

  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementA"), true);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementB"), false);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementD"), false);
}

TEST_F(FeatureManagementImplTest, GetFeatureLevel1Scope0) {
  libsegmentation::DeviceInfo device_info;
  device_info.set_feature_level(libsegmentation::DeviceInfo_FeatureLevel::
                                    DeviceInfo_FeatureLevel_FEATURE_LEVEL_1);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));

  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementA"), true);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementB"), false);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementD"), false);
}

TEST_F(FeatureManagementImplTest, GetFeatureLevel1Scope1) {
  libsegmentation::DeviceInfo device_info;
  device_info.set_feature_level(libsegmentation::DeviceInfo_FeatureLevel::
                                    DeviceInfo_FeatureLevel_FEATURE_LEVEL_1);
  device_info.set_scope_level(libsegmentation::DeviceInfo_ScopeLevel::
                                  DeviceInfo_ScopeLevel_SCOPE_LEVEL_1);
  EXPECT_TRUE(FeatureManagementUtil::WriteDeviceInfoToFile(device_info,
                                                           device_info_path_));

  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementA"), true);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementB"), true);
  EXPECT_EQ(feature_management_->IsFeatureEnabled("FeatureManagementD"), false);
}
#endif

}  // namespace segmentation
