// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fake/fake_service_manager.h"

#include <base/notreached.h>

namespace diagnostics {

FakeServiceManager::FakeServiceManager() : receiver_(this) {}

FakeServiceManager::~FakeServiceManager() = default;

void FakeServiceManager::Register(
    const std::string& service_name,
    mojo::PendingRemote<chromeos::mojo_service_manager::mojom::ServiceProvider>
        service_provider) {
  NOTIMPLEMENTED();
}

void FakeServiceManager::Request(const std::string& service_name,
                                 std::optional<base::TimeDelta> timeout,
                                 mojo::ScopedMessagePipeHandle receiver) {
  NOTIMPLEMENTED();
}

void FakeServiceManager::Query(const std::string& service_name,
                               QueryCallback callback) {
  NOTIMPLEMENTED();
}

void FakeServiceManager::AddServiceObserver(
    mojo::PendingRemote<chromeos::mojo_service_manager::mojom::ServiceObserver>
        observer) {
  NOTIMPLEMENTED();
}

}  // namespace diagnostics
