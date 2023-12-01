// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TRUNKS_DBUS_PROXY_H_
#define TRUNKS_TRUNKS_DBUS_PROXY_H_

#include <memory>
#include <string>
#include <utility>

#include <base/memory/weak_ptr.h>
#include <base/threading/platform_thread.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h>

#include "trunks/command_transceiver.h"
#include "trunks/trunks_export.h"

namespace trunks {

// TrunksDBusProxy is a CommandTransceiver implementation that forwards all
// commands to the trunksd D-Bus daemon. See TrunksDBusService for details on
// how the commands are handled once they reach trunksd. A TrunksDBusProxy
// instance must be used in only one thread.
class TRUNKS_EXPORT TrunksDBusProxy : public CommandTransceiver {
 public:
  TrunksDBusProxy();
  explicit TrunksDBusProxy(scoped_refptr<dbus::Bus> bus);
  TrunksDBusProxy(const std::string& name,
                  const std::string& path,
                  const std::string& interface);
  TrunksDBusProxy(const std::string& name,
                  const std::string& path,
                  const std::string& interface,
                  scoped_refptr<dbus::Bus> bus);
  ~TrunksDBusProxy() override;

  // Initializes the D-Bus client. Returns true on success.
  bool Init() override;

  // CommandTransceiver methods.
  void SendCommand(const std::string& command,
                   ResponseCallback callback) override;
  std::string SendCommandAndWait(const std::string& command) override;

  // Returns the service readiness flag. Forces re-check for readiness if
  // the flag is not set or |force_check| is passed.
  bool IsServiceReady(bool force_check);

  void set_init_timeout(base::TimeDelta init_timeout) {
    init_timeout_ = init_timeout;
  }
  void set_init_attempt_delay(base::TimeDelta init_attempt_delay) {
    init_attempt_delay_ = init_attempt_delay;
  }
  base::PlatformThreadId origin_thread_id_for_testing() {
    return origin_thread_id_;
  }
  void set_origin_thread_id_for_testing(
      base::PlatformThreadId testing_thread_id) {
    origin_thread_id_ = testing_thread_id;
  }
  void set_uma_reporter_for_testing(
      hwsec_foundation::TpmErrorUmaReporter* uma_reporter) {
    uma_reporter_.reset(uma_reporter);
  }

 private:
  friend class TrunksDBusProxyTest;

  TrunksDBusProxy(const TrunksDBusProxy&) = delete;
  TrunksDBusProxy& operator=(const TrunksDBusProxy&) = delete;

  void SendCommandInternal(const std::string& command,
                           ResponseCallback callback);
  std::string SendCommandAndWaitInternal(const std::string& command);

  // Checks service readiness, i.e. that trunksd is registered on dbus.
  bool CheckIfServiceReady();

  // Handles errors received from dbus.
  void OnError(ResponseCallback callback, brillo::Error* error);

  // Report metrics with |command| and |response|
  void ReportMetrics(const std::string& command, const std::string& response);
  void ReportMetricsCallback(ResponseCallback callback,
                             const std::string& command,
                             const std::string& response);

  base::WeakPtr<TrunksDBusProxy> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  // D-Bus interface description.
  const std::string dbus_name_;
  const std::string dbus_path_;
  const std::string dbus_interface_;

  bool service_ready_ = false;
  // Timeout waiting for trunksd service readiness on dbus when initializing.
  base::TimeDelta init_timeout_ = base::Seconds(30);
  // Delay between subsequent checks if trunksd is ready on dbus.
  base::TimeDelta init_attempt_delay_ = base::Milliseconds(300);

  base::PlatformThreadId origin_thread_id_;
  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* object_proxy_ = nullptr;
  std::unique_ptr<hwsec_foundation::TpmErrorUmaReporter> uma_reporter_;

  // Declared last so weak pointers are invalidated first on destruction.
  base::WeakPtrFactory<TrunksDBusProxy> weak_factory_{this};
};

}  // namespace trunks

#endif  // TRUNKS_TRUNKS_DBUS_PROXY_H_
