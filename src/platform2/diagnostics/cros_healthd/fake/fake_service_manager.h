// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SERVICE_MANAGER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SERVICE_MANAGER_H_

#include <optional>
#include <string>

#include <mojo/public/cpp/bindings/receiver.h>

#include "mojo_service_manager/lib/mojom/service_manager.mojom.h"

namespace diagnostics {

// Fake implementation of the ServiceManager interface.
class FakeServiceManager final
    : public chromeos::mojo_service_manager::mojom::ServiceManager {
 public:
  FakeServiceManager();
  FakeServiceManager(const FakeServiceManager&) = delete;
  FakeServiceManager& operator=(const FakeServiceManager&) = delete;
  ~FakeServiceManager() override;

  // Getter for the mojo receiver.
  mojo::Receiver<chromeos::mojo_service_manager::mojom::ServiceManager>&
  receiver() {
    return receiver_;
  }

  // chromeos::mojo_service_manager::mojom::ServiceManager overrides
  void Register(const std::string& service_name,
                mojo::PendingRemote<
                    chromeos::mojo_service_manager::mojom::ServiceProvider>
                    service_provider) override;
  void Request(const std::string& service_name,
               std::optional<base::TimeDelta> timeout,
               mojo::ScopedMessagePipeHandle receiver) override;
  void Query(const std::string& service_name, QueryCallback callback) override;
  void AddServiceObserver(
      mojo::PendingRemote<
          chromeos::mojo_service_manager::mojom::ServiceObserver> observer)
      override;

 private:
  mojo::Receiver<chromeos::mojo_service_manager::mojom::ServiceManager>
      receiver_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FAKE_FAKE_SERVICE_MANAGER_H_
