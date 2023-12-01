// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/strings/stringprintf.h>

#include "diagnostics/cros_healthd/system/ground_truth.h"
#include "diagnostics/cros_healthd/system/ground_truth_constants.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_exception.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

void LogCrosConfigFail(const std::string& path, const std::string& property) {
  LOG(ERROR) << "Failed to read cros_config: " << path << "/" << property;
}

std::string WrapUnsupportedString(const std::string& cros_config_property,
                                  const std::string& cros_config_value) {
  std::string msg = base::StringPrintf(
      "Not supported cros_config property [%s]: [%s]",
      cros_config_property.c_str(), cros_config_value.c_str());
  return msg;
}

}  // namespace

GroundTruth::GroundTruth(Context* context) : context_(context) {
  CHECK(context_);
}

GroundTruth::~GroundTruth() = default;

mojom::SupportStatusPtr GroundTruth::GetEventSupportStatus(
    mojom::EventCategoryEnum category) {
  switch (category) {
    // UnmappedEnumField.
    case mojom::EventCategoryEnum::kUnmappedEnumField:
      return mojom::SupportStatus::NewException(mojom::Exception::New(
          mojom::Exception::Reason::kUnexpected, "Got kUnmappedEnumField"));
    // Currently not supported.
    case mojom::EventCategoryEnum::kNetwork:
      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          "Not implemented. Please contact cros_healthd team.", nullptr));
    // Always supported.
    case mojom::EventCategoryEnum::kUsb:
    case mojom::EventCategoryEnum::kThunderbolt:
    case mojom::EventCategoryEnum::kBluetooth:
    case mojom::EventCategoryEnum::kPower:
    case mojom::EventCategoryEnum::kAudio:
    case mojom::EventCategoryEnum::kCrash:
      return mojom::SupportStatus::NewSupported(mojom::Supported::New());
    // Need to be determined by boxster/cros_config.
    case mojom::EventCategoryEnum::kKeyboardDiagnostic:
    case mojom::EventCategoryEnum::kTouchpad:
    case mojom::EventCategoryEnum::kLid: {
      std::vector<std::string> supported_form_factors = {
          cros_config_value::kClamshell,
          cros_config_value::kConvertible,
          cros_config_value::kDetachable,
      };
      auto form_factor = FormFactor();

      if (std::count(supported_form_factors.begin(),
                     supported_form_factors.end(), form_factor)) {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kFormFactor, form_factor),
          nullptr));
    }
    case mojom::EventCategoryEnum::kAudioJack: {
      auto has_audio_jack = HasAudioJack();
      if (has_audio_jack == "true") {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kHasAudioJack,
                                has_audio_jack),
          nullptr));
    }
    case mojom::EventCategoryEnum::kSdCard: {
      auto has_sd_reader = HasSdReader();
      if (has_sd_reader == "true") {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kHasSdReader,
                                has_sd_reader),
          nullptr));
    }
    case mojom::EventCategoryEnum::kHdmi: {
      auto has_hdmi = HasHdmi();
      if (has_hdmi == "true") {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kHasHdmi, has_hdmi),
          nullptr));
    }
    case mojom::EventCategoryEnum::kTouchscreen: {
      auto has_touchscreen = HasTouchscreen();
      if (has_touchscreen == "true") {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kHasTouchscreen,
                                has_touchscreen),
          nullptr));
    }
    case mojom::EventCategoryEnum::kStylusGarage: {
      auto stylus_category = StylusCategory();
      if (stylus_category == cros_config_value::kStylusCategoryInternal) {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kStylusCategory,
                                stylus_category),
          nullptr));
    }
    case mojom::EventCategoryEnum::kStylus: {
      auto stylus_category = StylusCategory();
      if (stylus_category == cros_config_value::kStylusCategoryInternal ||
          stylus_category == cros_config_value::kStylusCategoryExternal) {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kStylusCategory,
                                stylus_category),
          nullptr));
    }
  }
}

void GroundTruth::IsEventSupported(
    mojom::EventCategoryEnum category,
    mojom::CrosHealthdEventService::IsEventSupportedCallback callback) {
  auto status = GetEventSupportStatus(category);
  std::move(callback).Run(std::move(status));
}

mojom::SupportStatusPtr GroundTruth::GetRoutineSupportStatus(
    mojom::RoutineArgumentPtr routine_arg) {
  switch (routine_arg->which()) {
    // UnrecognizedArgument.
    case mojom::RoutineArgument::Tag::kUnrecognizedArgument:
      return mojom::SupportStatus::NewException(mojom::Exception::New(
          mojom::Exception::Reason::kUnexpected, "Got kUnrecognizedArgument"));
    // Always supported. There is no rule on the routine arguments.
    case mojom::RoutineArgument::Tag::kMemory:
    case mojom::RoutineArgument::Tag::kAudioDriver:
    case mojom::RoutineArgument::Tag::kCpuStress:
    case mojom::RoutineArgument::Tag::kCpuCache:
    case mojom::RoutineArgument::Tag::kPrimeSearch:
      return mojom::SupportStatus::NewSupported(mojom::Supported::New());
    // Need to be determined by boxster/cros_config.
    case mojom::RoutineArgument::Tag::kUfsLifetime: {
      auto storage_type = StorageType();
      if (storage_type == cros_config_value::kStorageTypeUfs) {
        return mojom::SupportStatus::NewSupported(mojom::Supported::New());
      }

      return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
          WrapUnsupportedString(cros_config_property::kStorageType,
                                storage_type),
          nullptr));
    }
    // Need to check the routine arguments.
    case mojom::RoutineArgument::Tag::kDiskRead: {
      auto& arg = routine_arg->get_disk_read();
      if (arg->disk_read_duration.InSeconds() <= 0) {
        return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
            "Disk read duration should not be zero after rounding towards zero "
            "to the nearest second",
            nullptr));
      }

      if (arg->file_size_mib == 0) {
        return mojom::SupportStatus::NewUnsupported(mojom::Unsupported::New(
            "Test file size should not be zero", nullptr));
      }

      if (arg->type == mojom::DiskReadTypeEnum::kUnmappedEnumField) {
        return mojom::SupportStatus::NewUnsupported(
            mojom::Unsupported::New("Unexpected disk read type", nullptr));
      }

      return mojom::SupportStatus::NewSupported(mojom::Supported::New());
    }
    // TODO(b/272217292): Check cros_config to see if the device has volume
    // buttons.
    case mojom::RoutineArgument::Tag::kVolumeButton:
      return mojom::SupportStatus::NewSupported(mojom::Supported::New());
  }
}

void GroundTruth::IsRoutineSupported(
    mojom::RoutineArgumentPtr routine_arg,
    mojom::CrosHealthdRoutinesService::IsRoutineSupportedCallback callback) {
  auto status = GetRoutineSupportStatus(std::move(routine_arg));
  std::move(callback).Run(std::move(status));
}

std::string GroundTruth::FormFactor() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kFormFactor);
}

std::string GroundTruth::StylusCategory() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kStylusCategory);
}

std::string GroundTruth::HasTouchscreen() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kHasTouchscreen);
}

std::string GroundTruth::HasHdmi() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kHasHdmi);
}

std::string GroundTruth::HasAudioJack() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kHasAudioJack);
}

std::string GroundTruth::HasSdReader() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kHasSdReader);
}

std::string GroundTruth::StorageType() {
  return ReadCrosConfig(cros_config_path::kHardwareProperties,
                        cros_config_property::kStorageType);
}

std::string GroundTruth::ReadCrosConfig(const std::string& path,
                                        const std::string& property) {
  std::string value;
  if (!context_->cros_config()->GetString(path, property, &value)) {
    LogCrosConfigFail(path, property);
    return "";
  }

  return value;
}

}  // namespace diagnostics
