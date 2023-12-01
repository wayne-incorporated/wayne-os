// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/diag/observers/routine_observer.h"

#include <iostream>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/callback_forward.h>
#include <base/values.h>

#include "diagnostics/cros_health_tool/output_util.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

base::Value::Dict ParseMemoryDetail(
    const mojom::MemoryRoutineDetailPtr& memory_detail) {
  base::Value::Dict output;
  base::Value::List passed_items;
  base::Value::List failed_items;

  for (auto passed_item : memory_detail->result->passed_items) {
    passed_items.Append(EnumToString(passed_item));
  }
  for (auto failed_item : memory_detail->result->failed_items) {
    failed_items.Append(EnumToString(failed_item));
  }

  SET_DICT(bytes_tested, memory_detail, &output);
  output.Set("passed_items", std::move(passed_items));
  output.Set("failed_items", std::move(failed_items));
  return output;
}

base::Value::Dict ParseAudioDriverDetail(
    const mojom::AudioDriverRoutineDetailPtr& audio_driver_detail) {
  base::Value::Dict output;

  SET_DICT(internal_card_detected, audio_driver_detail, &output);
  SET_DICT(audio_devices_succeed_to_open, audio_driver_detail, &output);

  return output;
}

base::Value::Dict ParseUfsLifetimeDetail(
    const mojom::UfsLifetimeRoutineDetailPtr& ufs_lifetime_detail) {
  base::Value::Dict output;

  SET_DICT(pre_eol_info, ufs_lifetime_detail, &output);
  SET_DICT(device_life_time_est_a, ufs_lifetime_detail, &output);
  SET_DICT(device_life_time_est_b, ufs_lifetime_detail, &output);

  return output;
}

}  // namespace

RoutineObserver::RoutineObserver(base::OnceClosure quit_closure)
    : receiver_{this /* impl */}, quit_closure_{std::move(quit_closure)} {}

RoutineObserver::~RoutineObserver() = default;

void RoutineObserver::SetFormatOutputCallback(
    base::OnceCallback<void(const base::Value::Dict&)> format_output_callback) {
  format_output_callback_ = std::move(format_output_callback);
}

void RoutineObserver::PrintOutput(const base::Value::Dict& output) {
  if (format_output_callback_) {
    std::move(format_output_callback_).Run(output);
    return;
  }
  std::cout << "Output: " << std::endl;
  OutputJson(output);
}

void RoutineObserver::OnRoutineStateChange(
    mojom::RoutineStatePtr state_update) {
  switch (state_update->state_union->which()) {
    case mojom::RoutineStateUnion::Tag::kFinished: {
      auto& finished_state = state_update->state_union->get_finished();
      std::cout << '\r' << "Running Progress: " << int(state_update->percentage)
                << std::endl;
      std::string passed_status =
          finished_state->has_passed ? "Passed" : "Failed";
      std::cout << ("Status: ") << passed_status << std::endl;
      switch (finished_state->detail->which()) {
        // These routines do not produce printable output. Printing passed or
        // failed is enough.
        case mojom::RoutineDetail::Tag::kCpuStress:
        case mojom::RoutineDetail::Tag::kDiskRead:
        case mojom::RoutineDetail::Tag::kCpuCache:
        case mojom::RoutineDetail::Tag::kPrimeSearch:
        case mojom::RoutineDetail::Tag::kVolumeButton:
          break;
        case mojom::RoutineDetail::Tag::kMemory:
          PrintOutput(ParseMemoryDetail(finished_state->detail->get_memory()));
          break;
        case mojom::RoutineDetail::Tag::kAudioDriver:
          PrintOutput(ParseAudioDriverDetail(
              finished_state->detail->get_audio_driver()));
          break;
        case mojom::RoutineDetail::Tag::kUfsLifetime:
          PrintOutput(ParseUfsLifetimeDetail(
              finished_state->detail->get_ufs_lifetime()));
          break;
      }
      std::move(quit_closure_).Run();
      return;
    }
    case mojom::RoutineStateUnion::Tag::kInitialized: {
      std::cout << "Initialized" << std::endl;
      return;
    }
    case mojom::RoutineStateUnion::Tag::kWaiting: {
      std::cout << '\r' << "Waiting: "
                << state_update->state_union->get_waiting()->reason
                << std::endl;
      return;
    }
    case mojom::RoutineStateUnion::Tag::kRunning: {
      std::cout << '\r' << "Running Progress: " << int(state_update->percentage)
                << std::flush;
      return;
    }
  }
}

}  // namespace diagnostics
