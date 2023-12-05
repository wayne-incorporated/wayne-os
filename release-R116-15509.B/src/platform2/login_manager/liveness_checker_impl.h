// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_LIVENESS_CHECKER_IMPL_H_
#define LOGIN_MANAGER_LIVENESS_CHECKER_IMPL_H_

#include <optional>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_piece_forward.h>
#include <base/time/time.h>

#include "login_manager/liveness_checker.h"
#include "login_manager/login_metrics.h"

namespace brillo {
class SafeFD;
}  // namespace brillo

namespace dbus {
class ObjectProxy;
class Response;
}  // namespace dbus

namespace login_manager {
class ProcessManagerServiceInterface;

// An implementation of LivenessChecker that pings a service (owned by Chrome)
// over D-Bus, and expects the response to a ping to come in reliably before the
// next ping is sent.  If not, it may ask |manager| to abort the browser
// process.
//
// Actual aborting behavior is controlled by the enable_aborting flag.
class LivenessCheckerImpl : public LivenessChecker {
 public:
  LivenessCheckerImpl(ProcessManagerServiceInterface* manager,
                      dbus::ObjectProxy* dbus_proxy,
                      bool enable_aborting,
                      base::TimeDelta interval,
                      LoginMetrics* metrics);
  LivenessCheckerImpl(const LivenessCheckerImpl&) = delete;
  LivenessCheckerImpl& operator=(const LivenessCheckerImpl&) = delete;

  ~LivenessCheckerImpl() override;

  // Implementation of LivenessChecker.
  void Start() override;
  void Stop() override;
  bool IsRunning() override;
  void DisableAborting() override;

  // If a liveness check is outstanding, kills the browser and clears liveness
  // tracking state.  This instance will be stopped at that point in time.
  // If no ping is outstanding, sends a liveness check to the browser over DBus,
  // then reschedules itself after interval.
  void CheckAndSendLivenessPing(base::TimeDelta interval);

  void set_manager(ProcessManagerServiceInterface* manager) {
    manager_ = manager;
  }

  // Override the /proc directory used for GetBrowserState().
  void SetProcForTests(base::FilePath&& proc_directory);

 private:
  // Handle async response to liveness ping by setting last_ping_acked_,
  // iff there is a successful response.
  void HandleAck(dbus::Response* response);

  // Opens a file (like "status" or "wchan") in the browser's /proc directory.
  // Returns a SafeFD if successful, nothing on error. If there is an error,
  // the error has already been logged and the caller does not need to log
  // another error.
  std::optional<brillo::SafeFD> OpenBrowserProcFile(
      base::StringPiece file_name);

  // Reads /proc/browser_pid/status and returns the state of the browser at
  // the current moment.
  LoginMetrics::BrowserState GetBrowserState();

  // Reads /proc/browser_pid/wchan and records the result in some format. (Right
  // now it just logs it; some day will also record in UMA).
  void RecordWchanState(LoginMetrics::BrowserState state);

  // Send requests to the kernel (via /proc/sysrq-trigger) asking that the
  // kernel dump info about what why processes are stuck. Results are in dmesg
  // logs, and not read by this process.
  void RequestKernelTraces();

  // Updates UMA stat recording the state of the browser process (running,
  // sleeping, uninterruptible wait, zombie, traced-or-stopped) at the moment
  // the liveness check times out. For sleep and wait states, also records what
  // the process was waiting for.
  void RecordStateForTimeout();

  ProcessManagerServiceInterface* manager_;  // Owned by the caller.
  dbus::ObjectProxy* dbus_proxy_;            // Owned by the caller.

  // Normally "/proc". Allows overriding of the /proc directory in tests.
  base::FilePath proc_directory_;

  bool enable_aborting_;
  const base::TimeDelta interval_;
  bool last_ping_acked_ = true;
  base::CancelableOnceClosure liveness_check_;
  base::TimeTicks ping_sent_;
  LoginMetrics* metrics_ = nullptr;
  base::WeakPtrFactory<LivenessCheckerImpl> weak_ptr_factory_{this};
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_LIVENESS_CHECKER_IMPL_H_
