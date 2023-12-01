// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_GROUND_TRUTH_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_GROUND_TRUTH_H_

#include <string>

#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_exception.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

class GroundTruth final {
 public:
  explicit GroundTruth(Context* context);
  GroundTruth(const GroundTruth&) = delete;
  GroundTruth& operator=(const GroundTruth&) = delete;
  ~GroundTruth();

  ash::cros_healthd::mojom::SupportStatusPtr GetEventSupportStatus(
      ash::cros_healthd::mojom::EventCategoryEnum category);
  void IsEventSupported(ash::cros_healthd::mojom::EventCategoryEnum category,
                        ash::cros_healthd::mojom::CrosHealthdEventService::
                            IsEventSupportedCallback callback);
  ash::cros_healthd::mojom::SupportStatusPtr GetRoutineSupportStatus(
      ash::cros_healthd::mojom::RoutineArgumentPtr routine_arg);
  void IsRoutineSupported(
      ash::cros_healthd::mojom::RoutineArgumentPtr routine_arg,
      ash::cros_healthd::mojom::CrosHealthdRoutinesService::
          IsRoutineSupportedCallback callback);

  // cros_config related functions.
  std::string FormFactor();
  std::string StylusCategory();
  std::string HasTouchscreen();
  std::string HasHdmi();
  std::string HasAudioJack();
  std::string HasSdReader();
  std::string StorageType();

 private:
  std::string ReadCrosConfig(const std::string& path,
                             const std::string& property);

  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_GROUND_TRUTH_H_
