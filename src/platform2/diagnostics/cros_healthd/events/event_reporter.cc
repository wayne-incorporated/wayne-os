// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/event_reporter.h"

#include <utility>

#include <chromeos/mojo/service_constants.h>

#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

EventReporter::EventReporter(Context* context) {
  ash_provider_.Register(context->mojo_service()->GetServiceManager(),
                         chromeos::mojo_services::kCrosHealthdAshEventReporter);
}

EventReporter::~EventReporter() = default;

void EventReporter::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  observers_.Add(std::move(observer));
}

void EventReporter::SendKeyboardDiagnosticEvent(
    ash::diagnostics::mojom::KeyboardDiagnosticEventInfoPtr info) {
  for (auto& observer : observers_) {
    observer->OnEvent(
        mojom::EventInfo::NewKeyboardDiagnosticEventInfo(info.Clone()));
  }
}

}  // namespace diagnostics
