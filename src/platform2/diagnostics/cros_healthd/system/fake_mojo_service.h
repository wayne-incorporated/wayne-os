// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_MOJO_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_MOJO_SERVICE_H_

#include <memory>

#include "diagnostics/cros_healthd/fake/fake_chromium_data_collector.h"
#include "diagnostics/cros_healthd/fake/fake_sensor_service.h"
#include "diagnostics/cros_healthd/fake/fake_service_manager.h"
#include "diagnostics/cros_healthd/system/mojo_service_impl.h"

namespace diagnostics {

// A fake implementation for unit tests.
class FakeMojoService : public MojoServiceImpl {
 public:
  FakeMojoService();
  FakeMojoService(const FakeMojoService&) = delete;
  FakeMojoService& operator=(const FakeMojoService&) = delete;
  ~FakeMojoService() override;

  // Initialize fake mojo services. Some unit tests don't create mojo
  // environment so we cannot initialize them in the constructor. Let the users
  // call this manually in unit tests.
  void InitializeFakeMojoService();

  // Getters for fake implementation.
  FakeServiceManager& fake_service_manager() { return fake_service_manager_; }

  FakeChromiumDataCollector& fake_chromium_data_collector() {
    return fake_chromium_data_collector_;
  }

  // Gets fake_chromium_data_collector.
  FakeSensorService& fake_sensor_service() { return fake_sensor_service_; }

 private:
  // Fake implementations.
  FakeServiceManager fake_service_manager_;
  FakeChromiumDataCollector fake_chromium_data_collector_;
  FakeSensorService fake_sensor_service_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_MOJO_SERVICE_H_
