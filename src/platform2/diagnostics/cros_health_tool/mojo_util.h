// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_MOJO_UTIL_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_MOJO_UTIL_H_

#include <optional>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/run_loop.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo_service_manager/lib/mojom/service_manager.mojom.h>

namespace diagnostics {

// Gets the mojo service manager interface from the initialized global
// instances.
chromeos::mojo_service_manager::mojom::ServiceManager* GetServiceManagerProxy();

// Requests a service and sets the disconnect handler to raise fatal error on
// disconnect.
template <typename T>
void RequestMojoServiceWithDisconnectHandler(const std::string& service_name,
                                             mojo::Remote<T>& remote) {
  GetServiceManagerProxy()->Request(
      service_name, /*timeout=*/std::nullopt,
      remote.BindNewPipeAndPassReceiver().PassPipe());
  remote.set_disconnect_with_reason_handler(base::BindOnce(
      [](const std::string& service_name, uint32_t error,
         const std::string& reason) {
        LOG(FATAL) << "Service " << service_name
                   << " disconnected, error: " << error
                   << ", reason: " << reason;
      },
      service_name));
}

// A helper class which uses base::RunLoop to make our mojo calls synchronized.
template <typename T>
class MojoResponseWaiter {
 public:
  MojoResponseWaiter() = default;
  MojoResponseWaiter(const MojoResponseWaiter&) = delete;
  MojoResponseWaiter& operator=(const MojoResponseWaiter&) = delete;
  ~MojoResponseWaiter() = default;

  // Creates a callback to get the mojo response. Passes this to the mojo calls.
  base::OnceCallback<void(T)> CreateCallback() {
    return base::BindOnce(&MojoResponseWaiter<T>::OnMojoResponseReceived,
                          weak_factory_.GetWeakPtr());
  }

  // Waits for the callback to be called and returns the response. Must be
  // called after `CreateCallback()` is used or it will block forever.
  T WaitForResponse() {
    run_loop_.Run();
    return std::move(data_);
  }

 private:
  void OnMojoResponseReceived(T response) {
    data_ = std::move(response);
    run_loop_.Quit();
  }

  // The run loop for waiting the callback to be called.
  base::RunLoop run_loop_;
  // The data to return.
  T data_;
  // Must be the last member.
  base::WeakPtrFactory<MojoResponseWaiter<T>> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_MOJO_UTIL_H_
