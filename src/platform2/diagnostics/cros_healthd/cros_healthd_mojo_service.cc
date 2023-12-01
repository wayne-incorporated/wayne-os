// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/cros_healthd_mojo_service.h"

#include <memory>
#include <sys/types.h>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <chromeos/mojo/service_constants.h>

#include "diagnostics/cros_healthd/fetchers/process_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_health_mojom = ::chromeos::network_health::mojom;

CrosHealthdMojoService::CrosHealthdMojoService(
    Context* context,
    FetchAggregator* fetch_aggregator,
    EventAggregator* event_aggregator)
    : RoutineService(context),
      context_(context),
      fetch_aggregator_(fetch_aggregator),
      event_aggregator_(event_aggregator) {
  DCHECK(context_);
  DCHECK(fetch_aggregator_);
  DCHECK(event_aggregator_);
  probe_provider_.Register(context->mojo_service()->GetServiceManager(),
                           chromeos::mojo_services::kCrosHealthdProbe);
  event_provider_.Register(context->mojo_service()->GetServiceManager(),
                           chromeos::mojo_services::kCrosHealthdEvent);
  routine_provider_.Register(context->mojo_service()->GetServiceManager(),
                             chromeos::mojo_services::kCrosHealthdRoutines);
}

CrosHealthdMojoService::~CrosHealthdMojoService() = default;

void CrosHealthdMojoService::AddBluetoothObserver(
    mojo::PendingRemote<mojom::CrosHealthdBluetoothObserver> observer) {
  LOG(FATAL) << "Deprecated cros healthd lid event API";
}

void CrosHealthdMojoService::AddLidObserver(
    mojo::PendingRemote<mojom::CrosHealthdLidObserver> observer) {
  LOG(FATAL) << "Deprecated cros healthd lid event API";
}

void CrosHealthdMojoService::AddPowerObserver(
    mojo::PendingRemote<mojom::CrosHealthdPowerObserver> observer) {
  event_aggregator_->AddObserver(std::move(observer));
}

void CrosHealthdMojoService::AddNetworkObserver(
    mojo::PendingRemote<network_health_mojom::NetworkEventsObserver> observer) {
  context_->network_health_adapter()->AddObserver(std::move(observer));
}

void CrosHealthdMojoService::AddAudioObserver(
    mojo::PendingRemote<mojom::CrosHealthdAudioObserver> observer) {
  event_aggregator_->AddObserver(std::move(observer));
}

void CrosHealthdMojoService::AddThunderboltObserver(
    mojo::PendingRemote<mojom::CrosHealthdThunderboltObserver> observer) {
  event_aggregator_->AddObserver(std::move(observer));
}

void CrosHealthdMojoService::AddUsbObserver(
    mojo::PendingRemote<mojom::CrosHealthdUsbObserver> observer) {
  event_aggregator_->AddObserver(std::move(observer));
}

void CrosHealthdMojoService::AddEventObserver(
    mojom::EventCategoryEnum category,
    mojo::PendingRemote<mojom::EventObserver> observer) {
  event_aggregator_->AddObserver(category, std::move(observer));
}

void CrosHealthdMojoService::IsEventSupported(
    mojom::EventCategoryEnum category, IsEventSupportedCallback callback) {
  event_aggregator_->IsEventSupported(category, std::move(callback));
}

void CrosHealthdMojoService::ProbeProcessInfo(
    uint32_t process_id, ProbeProcessInfoCallback callback) {
  ProcessFetcher(context_).FetchProcessInfo(static_cast<pid_t>(process_id),
                                            std::move(callback));
}

void CrosHealthdMojoService::ProbeTelemetryInfo(
    const std::vector<ProbeCategoryEnum>& categories,
    ProbeTelemetryInfoCallback callback) {
  return fetch_aggregator_->Run(categories, std::move(callback));
}

void CrosHealthdMojoService::ProbeMultipleProcessInfo(
    const std::optional<std::vector<uint32_t>>& process_ids,
    const bool ignore_single_process_info,
    ProbeMultipleProcessInfoCallback callback) {
  ProcessFetcher(context_).FetchMultipleProcessInfo(
      process_ids, ignore_single_process_info, std::move(callback));
}

}  // namespace diagnostics
