/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/feature_profile.h"

#include <string>
#include <utility>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/json/json_reader.h>
#include <base/test/task_environment.h>
#include <base/test/test_timeouts.h>
#include <gtest/gtest.h>

namespace cros {

namespace {

base::Value::Dict CreateFakeFeatureProfile(std::string json_str) {
  auto result = base::JSONReader::ReadAndReturnValueWithError(json_str);
  CHECK(result.has_value() && result->is_dict());
  return std::move(result.value().GetDict());
}

}  // namespace

TEST(FeatureProfile, BasicCorrectnessTest) {
  base::test::SingleThreadTaskEnvironment task_environment;

  std::string profile = R"({
    "acme": {
      "feature_set": [ {
        "type": "hdrnet",
        "config_file_path": "/etc/camera/hdrnet_config.json"
      }, {
        "type": "gcam_ae",
        "config_file_path": "/etc/camera/gcam_ae_config.json"
      } ]
    }
  })";

  // Only the specified features are enabled.
  {
    FeatureProfile::DeviceMetadata metadata = {
        .model_name = "acme",
    };

    FeatureProfile p(CreateFakeFeatureProfile(profile), metadata);
    EXPECT_TRUE(p.IsEnabled(FeatureProfile::FeatureType::kHdrnet));
    EXPECT_EQ(p.GetConfigFilePath(FeatureProfile::FeatureType::kHdrnet),
              base::FilePath("/etc/camera/hdrnet_config.json"));
    EXPECT_TRUE(p.IsEnabled(FeatureProfile::FeatureType::kGcamAe));
    EXPECT_EQ(p.GetConfigFilePath(FeatureProfile::FeatureType::kGcamAe),
              base::FilePath("/etc/camera/gcam_ae_config.json"));
    EXPECT_FALSE(p.IsEnabled(FeatureProfile::FeatureType::kAutoFraming));
  }

  // All features should be disabled if there's no feature profile set.
  {
    FeatureProfile::DeviceMetadata metadata = {
        .model_name = "foo",
    };

    FeatureProfile p(CreateFakeFeatureProfile(profile), metadata);
    EXPECT_FALSE(p.IsEnabled(FeatureProfile::FeatureType::kHdrnet));
    EXPECT_FALSE(p.IsEnabled(FeatureProfile::FeatureType::kAutoFraming));
  }
}

TEST(FeatureProfile, ModuleAndSensorIdTest) {
  base::test::SingleThreadTaskEnvironment task_environment;

  {
    std::string profile = R"({
      "acme": {
        "feature_set": [ {
          "type": "hdrnet",
          "enable_on": {
            "module_id": "acme_module",
            "sensor_id": "acme_sensor"
          },
          "config_file_path": "/etc/camera/hdrnet_config.json"
        }, {
          "type": "gcam_ae",
          "enable_on": {
            "module_id": "foo_module",
            "sensor_id": "foo_sensor"
          },
          "config_file_path": "/etc/camera/gcam_ae.json"
        }, {
          "type": "face_detection",
          "enable_on": {
            "sensor_id": "acme_sensor"
          },
          "config_file_path": "/etc/camera/face_detection.json"
        }, {
          "type": "auto_framing",
          "enable_on": {
            "module_id": "foo_module",
            "sensor_id": "acme_sensor"
          },
          "config_file_path": "/etc/camera/auto_framing.json"
        } ]
      }
    })";

    FeatureProfile::DeviceMetadata metadata = {
        .model_name = "acme",
        .camera_info = {
            {.module_id = "acme_module", .sensor_id = "acme_sensor"},
        }};

    FeatureProfile p(CreateFakeFeatureProfile(profile), metadata);

    // Enabled as both module and sensor id match.
    EXPECT_TRUE(p.IsEnabled(FeatureProfile::FeatureType::kHdrnet));

    // Disabled as module and sensor id mismatch.
    EXPECT_FALSE(p.IsEnabled(FeatureProfile::FeatureType::kGcamAe));

    // Enabled as sensor id match and module id unspecified.
    EXPECT_TRUE(p.IsEnabled(FeatureProfile::FeatureType::kFaceDetection));

    // Disabled as module id mismatch.
    EXPECT_FALSE(p.IsEnabled(FeatureProfile::FeatureType::kAutoFraming));
  }
  {
    std::string profile = R"({
      "some_model": {
        "feature_set": [ {
          "type": "hdrnet",
          "enable_on": {
            "module_id": "acme_module"
          },
          "config_file_path": "/etc/camera/acme.json"
        }, {
          "type": "hdrnet",
          "enable_on": {
            "sensor_id": "foo_sensor"
          },
          "config_file_path": "/etc/camera/foo.json"
        } ]
      }
    })";

    // Devices with the same model should load different feature setting based
    // on the camera module/sensor info.
    FeatureProfile::DeviceMetadata acme_metadata = {
        .model_name = "some_model",
        .camera_info = {
            {.module_id = "acme_module", .sensor_id = "acme_sensor"},
        }};
    FeatureProfile acme_profile(CreateFakeFeatureProfile(profile),
                                acme_metadata);
    EXPECT_TRUE(acme_profile.IsEnabled(FeatureProfile::FeatureType::kHdrnet));
    EXPECT_EQ(
        acme_profile.GetConfigFilePath(FeatureProfile::FeatureType::kHdrnet),
        base::FilePath("/etc/camera/acme.json"));

    FeatureProfile::DeviceMetadata foo_metadata = {
        .model_name = "some_model",
        .camera_info = {
            {.module_id = "foo_module", .sensor_id = "foo_sensor"},
        }};
    FeatureProfile foo_profile(CreateFakeFeatureProfile(profile), foo_metadata);
    EXPECT_TRUE(foo_profile.IsEnabled(FeatureProfile::FeatureType::kHdrnet));
    EXPECT_EQ(
        foo_profile.GetConfigFilePath(FeatureProfile::FeatureType::kHdrnet),
        base::FilePath("/etc/camera/foo.json"));
  }
}

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  ::testing::InitGoogleTest(&argc, argv);
  LOG_ASSERT(logging::InitLogging(logging::LoggingSettings()));
  return RUN_ALL_TESTS();
}
