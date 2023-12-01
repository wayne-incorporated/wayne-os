// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ROUTINE_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ROUTINE_SERVICE_H_

#include <memory>
#include <string>

#include <mojo/public/cpp/bindings/unique_receiver_set.h>

#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/cros_healthd/system/ground_truth.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

class RoutineService
    : public ash::cros_healthd::mojom::CrosHealthdRoutinesService {
 public:
  explicit RoutineService(Context* context);
  RoutineService(const RoutineService&) = delete;
  RoutineService& operator=(const RoutineService&) = delete;
  ~RoutineService() override;

  // ash::cros_healthd::mojom::CrosHealthdRoutinesService overrides:
  void CreateRoutine(
      ash::cros_healthd::mojom::RoutineArgumentPtr routine_arg,
      mojo::PendingReceiver<ash::cros_healthd::mojom::RoutineControl>
          routine_receiver) override;
  void IsRoutineSupported(
      ash::cros_healthd::mojom::RoutineArgumentPtr routine_arg,
      ash::cros_healthd::mojom::CrosHealthdRoutinesService::
          IsRoutineSupportedCallback callback) override;

 private:
  // A helper function that adds a routine into the routine receiver set and
  // perform necessary setup.
  void AddRoutine(
      std::unique_ptr<BaseRoutineControl> routine,
      mojo::PendingReceiver<ash::cros_healthd::mojom::RoutineControl>
          routine_receiver);

  // A function to be run by Routines in CrosHealthdRoutineService. When routine
  // encounters an exception, this function should be able to disconnect its
  // mojo connection.
  void OnRoutineException(mojo::ReceiverId receiver_id,
                          uint32_t error,
                          const std::string& reason);

  // A unique receiver set will hold both the mojo receiver and the routine
  // implementation for lifecycle management.
  mojo::UniqueReceiverSet<ash::cros_healthd::mojom::RoutineControl>
      receiver_set_;

  // Unowned. The following instances should outlive this instance.
  Context* const context_ = nullptr;

  // Used for performing the routine support status check.
  std::unique_ptr<GroundTruth> ground_truth_ = nullptr;

  // Must be the last class member.
  base::WeakPtrFactory<RoutineService> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_ROUTINE_SERVICE_H_
