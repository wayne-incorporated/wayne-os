// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/system/ground_truth.h"
#include "diagnostics/cros_healthd/system/ground_truth_constants.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_exception.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

class GroundTruthTest : public testing::Test {
 protected:
  GroundTruthTest() = default;
  GroundTruthTest(const GroundTruthTest&) = delete;
  GroundTruthTest& operator=(const GroundTruthTest&) = delete;

  void ExpectEventSupported(mojom::EventCategoryEnum category) {
    ExpectEventStatus(category, mojom::SupportStatus::Tag::kSupported);
  }

  void ExpectEventUnsupported(mojom::EventCategoryEnum category) {
    ExpectEventStatus(category, mojom::SupportStatus::Tag::kUnsupported);
  }

  void ExpectEventException(mojom::EventCategoryEnum category) {
    ExpectEventStatus(category, mojom::SupportStatus::Tag::kException);
  }

  void ExpectRoutineSupported(mojom::RoutineArgumentPtr arg) {
    ExpectRoutineStatus(std::move(arg), mojom::SupportStatus::Tag::kSupported);
  }

  void ExpectRoutineUnsupported(mojom::RoutineArgumentPtr arg) {
    ExpectRoutineStatus(std::move(arg),
                        mojom::SupportStatus::Tag::kUnsupported);
  }

  void SetCrosConfig(const std::string& path,
                     const std::string& property,
                     const std::string& value) {
    mock_context_.fake_cros_config()->SetString(path, property, value);
  }

 private:
  // This makes debugging easier when there is an error in unittest.
  std::string TagToString(const mojom::SupportStatus::Tag tag) {
    switch (tag) {
      case mojom::SupportStatus::Tag::kUnmappedUnionField:
        return "kUnmappedUnionField";
      case mojom::SupportStatus::Tag::kException:
        return "kException";
      case mojom::SupportStatus::Tag::kSupported:
        return "kSupported";
      case mojom::SupportStatus::Tag::kUnsupported:
        return "kUnsupported";
    }
  }

  void ExpectEventStatus(mojom::EventCategoryEnum category,
                         mojom::SupportStatus::Tag expect_status) {
    auto status = ground_truth_.GetEventSupportStatus(category);
    EXPECT_EQ(TagToString(status->which()), TagToString(expect_status));
  }

  void ExpectRoutineStatus(mojom::RoutineArgumentPtr arg,
                           mojom::SupportStatus::Tag expect_status) {
    auto status = ground_truth_.GetRoutineSupportStatus(std::move(arg));
    EXPECT_EQ(TagToString(status->which()), TagToString(expect_status));
  }

  MockContext mock_context_;
  GroundTruth ground_truth_{&mock_context_};
};

TEST_F(GroundTruthTest, AlwaysSupportedEvents) {
  ExpectEventSupported(mojom::EventCategoryEnum::kUsb);
  ExpectEventSupported(mojom::EventCategoryEnum::kThunderbolt);
  ExpectEventSupported(mojom::EventCategoryEnum::kBluetooth);
  ExpectEventSupported(mojom::EventCategoryEnum::kPower);
  ExpectEventSupported(mojom::EventCategoryEnum::kAudio);
}

TEST_F(GroundTruthTest, AlwaysSupportedRoutines) {
  ExpectRoutineSupported(
      mojom::RoutineArgument::NewMemory(mojom::MemoryRoutineArgument::New()));
  ExpectRoutineSupported(mojom::RoutineArgument::NewAudioDriver(
      mojom::AudioDriverRoutineArgument::New()));
  ExpectRoutineSupported(mojom::RoutineArgument::NewCpuStress(
      mojom::CpuStressRoutineArgument::New()));
  ExpectRoutineSupported(mojom::RoutineArgument::NewCpuCache(
      mojom::CpuCacheRoutineArgument::New()));
}

TEST_F(GroundTruthTest, CurrentUnsupported) {
  ExpectEventUnsupported(mojom::EventCategoryEnum::kNetwork);
}

TEST_F(GroundTruthTest, UnmappedField) {
  ExpectEventException(mojom::EventCategoryEnum::kUnmappedEnumField);
}

TEST_F(GroundTruthTest, LidEvent) {
  std::vector<std::pair</*form-factor=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {cros_config_value::kClamshell, true},
          {cros_config_value::kConvertible, true},
          {cros_config_value::kDetachable, true},
          {cros_config_value::kChromebase, false},
          {cros_config_value::kChromebox, false},
          {cros_config_value::kChromebit, false},
          {cros_config_value::kChromeslate, false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kLid);

  for (const auto& [form_factor, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kFormFactor, form_factor);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kLid);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kLid);
    }
  }
}

TEST_F(GroundTruthTest, StylusGarageEvent) {
  std::vector<std::pair</*stylus-category=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {cros_config_value::kStylusCategoryInternal, true},
          {cros_config_value::kStylusCategoryUnknown, false},
          {cros_config_value::kStylusCategoryNone, false},
          {cros_config_value::kStylusCategoryExternal, false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kStylusGarage);

  for (const auto& [stylus_category, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kStylusCategory, stylus_category);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kStylusGarage);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kStylusGarage);
    }
  }
}

TEST_F(GroundTruthTest, StylusEvent) {
  std::vector<std::pair</*stylus-category=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {cros_config_value::kStylusCategoryInternal, true},
          {cros_config_value::kStylusCategoryExternal, true},
          {cros_config_value::kStylusCategoryUnknown, false},
          {cros_config_value::kStylusCategoryNone, false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kStylus);

  for (const auto& [stylus_category, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kStylusCategory, stylus_category);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kStylus);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kStylus);
    }
  }
}

TEST_F(GroundTruthTest, TouchscreenEvent) {
  std::vector<std::pair</*has-touchscreen=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {"true", true},
          {"false", false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kTouchscreen);

  for (const auto& [has_touchscreen, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kHasTouchscreen, has_touchscreen);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kTouchscreen);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kTouchscreen);
    }
  }
}

TEST_F(GroundTruthTest, TouchpadEvent) {
  std::vector<std::pair</*form-factor=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {cros_config_value::kClamshell, true},
          {cros_config_value::kConvertible, true},
          {cros_config_value::kDetachable, true},
          {cros_config_value::kChromebase, false},
          {cros_config_value::kChromebox, false},
          {cros_config_value::kChromebit, false},
          {cros_config_value::kChromeslate, false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kTouchpad);

  for (const auto& [form_factor, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kFormFactor, form_factor);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kTouchpad);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kTouchpad);
    }
  }
}

TEST_F(GroundTruthTest, KeyboardDiagnosticEvent) {
  std::vector<std::pair</*form-factor=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {cros_config_value::kClamshell, true},
          {cros_config_value::kConvertible, true},
          {cros_config_value::kDetachable, true},
          {cros_config_value::kChromebase, false},
          {cros_config_value::kChromebox, false},
          {cros_config_value::kChromebit, false},
          {cros_config_value::kChromeslate, false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kKeyboardDiagnostic);

  for (const auto& [form_factor, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kFormFactor, form_factor);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kKeyboardDiagnostic);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kKeyboardDiagnostic);
    }
  }
}

TEST_F(GroundTruthTest, HdmiEvent) {
  std::vector<std::pair</*has-hdmi=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {"true", true},
          {"false", false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kHdmi);

  for (const auto& [has_hdmi, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kHasHdmi, has_hdmi);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kHdmi);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kHdmi);
    }
  }
}

TEST_F(GroundTruthTest, AudioJackEvent) {
  std::vector<std::pair</*has-audio-jack=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {"true", true},
          {"false", false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kAudioJack);

  for (const auto& [has_audio_jack, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kHasAudioJack, has_audio_jack);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kAudioJack);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kAudioJack);
    }
  }
}

TEST_F(GroundTruthTest, SdCardEvent) {
  std::vector<std::pair</*has-sd-reader=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {"true", true},
          {"false", false},
          {"Others", false},
      };

  // Test not set the cros_config first to simulate file not found.
  ExpectEventUnsupported(mojom::EventCategoryEnum::kSdCard);

  for (const auto& [has_sd_reader, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kHasSdReader, has_sd_reader);
    if (supported) {
      ExpectEventSupported(mojom::EventCategoryEnum::kSdCard);
    } else {
      ExpectEventUnsupported(mojom::EventCategoryEnum::kSdCard);
    }
  }
}

TEST_F(GroundTruthTest, UfsLifetimeRoutine) {
  std::vector<std::pair</*storage-type=*/std::string, /*supported=*/bool>>
      test_combinations = {
          {cros_config_value::kStorageTypeUfs, true},
          {cros_config_value::kStorageTypeUnknown, false},
          {cros_config_value::kStorageTypeEmmc, false},
          {cros_config_value::kStorageTypeNvme, false},
          {cros_config_value::kStorageTypeSata, false},
          {cros_config_value::kStorageTypeBridgedEmmc, false},
          {"Others", false},
      };
  mojom::UfsLifetimeRoutineArgument arg;

  // Test not set the cros_config first to simulate file not found.
  ExpectRoutineUnsupported(mojom::RoutineArgument::NewUfsLifetime(arg.Clone()));

  for (const auto& [storage_type, supported] : test_combinations) {
    SetCrosConfig(cros_config_path::kHardwareProperties,
                  cros_config_property::kStorageType, storage_type);
    if (supported) {
      ExpectRoutineSupported(
          mojom::RoutineArgument::NewUfsLifetime(arg.Clone()));
    } else {
      ExpectRoutineUnsupported(
          mojom::RoutineArgument::NewUfsLifetime(arg.Clone()));
    }
  }
}

TEST_F(GroundTruthTest, DiskReadRoutine) {
  auto arg = mojom::DiskReadRoutineArgument::New();
  arg->type = mojom::DiskReadTypeEnum::kLinearRead;
  arg->disk_read_duration = base::Seconds(1);
  arg->file_size_mib = 1;

  ExpectRoutineSupported(mojom::RoutineArgument::NewDiskRead(std::move(arg)));
}

TEST_F(GroundTruthTest, DiskReadRoutineUnknownType) {
  auto arg = mojom::DiskReadRoutineArgument::New();
  arg->type = mojom::DiskReadTypeEnum::kUnmappedEnumField;
  arg->disk_read_duration = base::Seconds(1);
  arg->file_size_mib = 1;

  ExpectRoutineUnsupported(mojom::RoutineArgument::NewDiskRead(std::move(arg)));
}

TEST_F(GroundTruthTest, DiskReadRoutineZeroDuration) {
  auto arg = mojom::DiskReadRoutineArgument::New();
  arg->type = mojom::DiskReadTypeEnum::kLinearRead;
  arg->disk_read_duration = base::Seconds(0);
  arg->file_size_mib = 1;

  ExpectRoutineUnsupported(mojom::RoutineArgument::NewDiskRead(std::move(arg)));
}

TEST_F(GroundTruthTest, DiskReadRoutineZeroFileSize) {
  auto arg = mojom::DiskReadRoutineArgument::New();
  arg->type = mojom::DiskReadTypeEnum::kLinearRead;
  arg->disk_read_duration = base::Seconds(1);
  arg->file_size_mib = 0;

  ExpectRoutineUnsupported(mojom::RoutineArgument::NewDiskRead(std::move(arg)));
}

}  // namespace
}  // namespace diagnostics
