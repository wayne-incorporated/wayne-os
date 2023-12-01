// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/routine_service.h"

#include <utility>

#include "diagnostics/cros_healthd/routines/audio/audio_driver.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/cpu_cache_v2.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/cpu_stress_v2.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/memory_v2.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/prime_search_v2.h"
#include "diagnostics/cros_healthd/routines/storage/disk_read_v2.h"
#include "diagnostics/cros_healthd/routines/storage/ufs_lifetime.h"
#include "diagnostics/cros_healthd/routines/volume_button/volume_button.h"
#include "diagnostics/mojom/public/cros_healthd_exception.mojom.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

RoutineService::RoutineService(Context* context) : context_(context) {
  CHECK(context_);
  ground_truth_ = std::make_unique<GroundTruth>(context_);
}

RoutineService::~RoutineService() = default;

void RoutineService::CreateRoutine(
    mojom::RoutineArgumentPtr routine_arg,
    mojo::PendingReceiver<mojom::RoutineControl> routine_receiver) {
  switch (routine_arg->which()) {
    case mojom::RoutineArgument::Tag::kPrimeSearch:
      AddRoutine(std::make_unique<PrimeSearchRoutineV2>(
                     context_, routine_arg->get_prime_search()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kMemory:
      AddRoutine(std::make_unique<MemoryRoutineV2>(context_,
                                                   routine_arg->get_memory()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kAudioDriver:
      AddRoutine(std::make_unique<AudioDriverRoutine>(
                     context_, routine_arg->get_audio_driver()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kCpuStress:
      AddRoutine(std::make_unique<CpuStressRoutineV2>(
                     context_, routine_arg->get_cpu_stress()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kUfsLifetime:
      AddRoutine(std::make_unique<UfsLifetimeRoutine>(
                     context_, routine_arg->get_ufs_lifetime()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kDiskRead:
      if (auto routine =
              DiskReadRoutineV2::Create(context_, routine_arg->get_disk_read());
          routine.has_value()) {
        AddRoutine(std::move(routine.value()), std::move(routine_receiver));
      } else {
        routine_receiver.ResetWithReason(
            static_cast<uint32_t>(
                mojom::RoutineControlExceptionEnum::kNotSupported),
            routine.error());
      }
      break;
    case mojom::RoutineArgument::Tag::kCpuCache:
      AddRoutine(std::make_unique<CpuCacheRoutineV2>(
                     context_, routine_arg->get_cpu_cache()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kVolumeButton:
      AddRoutine(std::make_unique<VolumeButtonRoutine>(
                     context_, routine_arg->get_volume_button()),
                 std::move(routine_receiver));
      break;
    case mojom::RoutineArgument::Tag::kUnrecognizedArgument:
      LOG(ERROR) << "Routine Argument not recognized/supported";
      routine_receiver.ResetWithReason(
          static_cast<uint32_t>(
              mojom::RoutineControlExceptionEnum::kNotSupported),
          "Routine Argument not recognized/supported");
      break;
  }
}

void RoutineService::IsRoutineSupported(
    mojom::RoutineArgumentPtr routine_arg,
    mojom::CrosHealthdRoutinesService::IsRoutineSupportedCallback callback) {
  ground_truth_->IsRoutineSupported(std::move(routine_arg),
                                    std::move(callback));
}

void RoutineService::AddRoutine(
    std::unique_ptr<BaseRoutineControl> routine,
    mojo::PendingReceiver<mojom::RoutineControl> routine_receiver) {
  auto routine_ptr = routine.get();
  mojo::ReceiverId receiver_id =
      receiver_set_.Add(std::move(routine), std::move(routine_receiver));
  routine_ptr->SetOnExceptionCallback(
      base::BindOnce(&RoutineService::OnRoutineException,
                     weak_ptr_factory_.GetWeakPtr(), receiver_id));
}

void RoutineService::OnRoutineException(mojo::ReceiverId receiver_id,
                                        uint32_t error,
                                        const std::string& reason) {
  if (!receiver_set_.HasReceiver(receiver_id)) {
    LOG(ERROR) << "Receiver ID not found in receiver set: " << receiver_id;
    return;
  }
  receiver_set_.RemoveWithReason(receiver_id, error, reason);
}

}  // namespace diagnostics
