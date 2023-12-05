// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SESSION_MANAGER_SERVICE_H_
#define LOGIN_MANAGER_SESSION_MANAGER_SERVICE_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <brillo/asynchronous_signal_handler.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <install_attributes/libinstallattributes.h>

#include "login_manager/android_oci_wrapper.h"
#include "login_manager/child_exit_handler.h"
#include "login_manager/crossystem_impl.h"
#include "login_manager/device_identifier_generator.h"
#include "login_manager/key_generator.h"
#include "login_manager/liveness_checker.h"
#include "login_manager/policy_key.h"
#include "login_manager/process_manager_service_interface.h"
#include "login_manager/session_manager_impl.h"
#include "login_manager/session_manager_interface.h"
#include "login_manager/vpd_process_impl.h"

struct signalfd_siginfo;

class MessageLoop;

namespace login_manager {

class BrowserJobInterface;
class ChildExitDispatcher;
class ChromeFeaturesServiceClient;
class LoginMetrics;
class NssUtil;
class SystemUtils;

// Provides methods for running the browser, watching its progress, and
// restarting it if need be.
//
// Once the browser is run, it will be restarted perpetually, UNLESS
// |magic_chrome_file| exists, or this process receives a termination signal.
// Also provides a wrapper that exports SessionManagerImpl methods via
// D-Bus.
class SessionManagerService
    : public base::RefCountedThreadSafe<SessionManagerService>,
      public SessionManagerImpl::Delegate,
      public ChildExitHandler,
      public ProcessManagerServiceInterface {
 public:
  enum ExitCode {
    SUCCESS = 0,
    CRASH_WHILE_RESTART_DISABLED = 1,
    CHILD_EXITING_TOO_FAST = 2,
    MUST_WIPE_DEVICE = 3,
    // Used in upstart to signal that the session wasn't started since the
    // device was already shutting down.
    DEVICE_SHUTTING_DOWN = 4,
  };

  // Path to flag file indicating that a user has logged in since last boot.
  static const char kLoggedInFlag[];

  // If you want to call any of these setters, you should do so before calling
  // any other methods on this class.
  class TestApi {
   public:
    void set_systemutils(SystemUtils* utils) {
      session_manager_service_->system_ = utils;
    }
    void set_login_metrics(LoginMetrics* metrics) {
      session_manager_service_->login_metrics_ = metrics;
    }
    void set_liveness_checker(LivenessChecker* checker) {
      session_manager_service_->liveness_checker_.reset(checker);
    }
    void set_session_manager(SessionManagerInterface* impl) {
      session_manager_service_->impl_.reset(impl);
    }
    // Sets whether the the manager exits when a child finishes.
    void set_exit_on_child_done(bool do_exit) {
      session_manager_service_->exit_on_child_done_ = do_exit;
    }
    void set_aborted_browser_pid_path(const base::FilePath& path) {
      session_manager_service_->aborted_browser_pid_path_ = path;
    }
    void set_vm_concierge_proxy(dbus::ObjectProxy* proxy) {
      session_manager_service_->vm_concierge_dbus_proxy_ = proxy;
    }
    void set_vm_concierge_available(bool available) {
      session_manager_service_->vm_concierge_available_ = available;
    }

    void CleanupChildrenBeforeExit() {
      session_manager_service_->CleanupChildrenBeforeExit(ExitCode::SUCCESS);
    }

    // Cause handling of faked-out exit of a child process.
    void ScheduleChildExit(pid_t pid, int status);

    // Trigger and handle SessionManagerImpl initialization.
    bool InitializeImpl() { return session_manager_service_->InitializeImpl(); }

   private:
    friend class SessionManagerService;
    explicit TestApi(SessionManagerService* session_manager_service)
        : session_manager_service_(session_manager_service) {}
    SessionManagerService* session_manager_service_;
  };

  SessionManagerService(std::unique_ptr<BrowserJobInterface> child_job,
                        uid_t uid,
                        std::optional<base::FilePath> ns_path,
                        base::TimeDelta kill_timeout,
                        bool enable_browser_abort_on_hang,
                        base::TimeDelta hang_detection_interval,
                        LoginMetrics* metrics,
                        SystemUtils* system);
  SessionManagerService(const SessionManagerService&) = delete;
  SessionManagerService& operator=(const SessionManagerService&) = delete;

  ~SessionManagerService() override;

  // TestApi exposes internal routines for testing purposes.
  TestApi test_api() { return TestApi(this); }

  bool Initialize();

  // Tears down objects set up during Initialize(), cleans up child processes,
  // and announces that the user session has stopped over DBus.
  void Finalize();

  ExitCode exit_code() { return exit_code_; }

  // SessionManagerImpl:
  void LockScreen() override;
  void RestartDevice(const std::string& description) override;

  // ProcessManagerServiceInterface:
  void ScheduleShutdown() override;
  void RunBrowser() override;
  void AbortBrowserForHang() override;
  void SetBrowserTestArgs(const std::vector<std::string>& args) override;
  void SetBrowserArgs(const std::vector<std::string>& args) override;
  void SetBrowserAdditionalEnvironmentalVariables(
      const std::vector<std::string>& env_vars) override;
  void RestartBrowser() override;
  void SetBrowserSessionForUser(const std::string& account_id,
                                const std::string& userhash) override;
  void SetFlagsForUser(const std::string& account_id,
                       const std::vector<std::string>& flags) override;
  void SetFeatureFlagsForUser(
      const std::string& account_id,
      const std::vector<std::string>& feature_flags,
      const std::map<std::string, std::string>& origin_list_flags) override;
  void SetBrowserDataMigrationArgsForUser(const std::string& userhash,
                                          const std::string& mode) override;
  void SetBrowserDataBackwardMigrationArgsForUser(
      const std::string& userhash) override;
  bool IsBrowser(pid_t pid) override;
  std::optional<pid_t> GetBrowserPid() const override;
  base::TimeTicks GetLastBrowserRestartTime() override;
  void SetMultiUserSessionStarted() override;

  // ChildExitHandler overrides:
  // Handles only browser exit (i.e. IsBrowser(pid) returns true).
  // Re-runs the browser, unless one of the following is true:
  //  The screen is supposed to be locked,
  //  UI shutdown is in progress,
  //  The child indicates that it should not run anymore, or
  //  ShouldRunBrowser() indicates the browser should not run anymore.
  bool HandleExit(const siginfo_t& info) override;

  // Set all changed signal handlers back to the default behavior.
  static void RevertHandlers();

 private:
  // |data| is a SessionManagerService*.
  static DBusHandlerResult FilterMessage(DBusConnection* conn,
                                         DBusMessage* message,
                                         void* data);

  // Set up any necessary signal handlers.
  void SetUpHandlers();

  // Returns appropriate child-killing timeout, depending on flag file state.
  base::TimeDelta GetKillTimeout();

  // Initializes policy subsystems which, among other things, finds and
  // validates the stored policy signing key if one is present.
  // A corrupted policy key means that the device needs to have its data wiped.
  // We trigger a reboot and then wipe (most of) the stateful partition.
  bool InitializeImpl();

  // Initializes connection to DBus system bus, and creates proxies to talk
  // to other needed services. Failure is fatal.
  void InitializeDBus();

  // Initializes suspend delays with powerd and registers callbacks for
  // suspend and resume.
  void InitializeSuspendDelays();

  // Tears down DBus connection. Failure is fatal.
  void ShutDownDBus();

  // Tell us that, if we want, we can cause a graceful exit from MessageLoop.
  void AllowGracefulExitOrRunForever();

  // Sets the proccess' exit code immediately and posts a QuitClosure to the
  // main event loop.
  void SetExitAndScheduleShutdown(ExitCode code);

  // Terminate all children, with increasing prejudice.
  void CleanupChildrenBeforeExit(ExitCode code);

  // Callback when receiving a termination signal.
  bool OnTerminationSignal(const struct signalfd_siginfo& info);

  // Called when the owner of the vm_concierge D-Bus service changes.
  void VmConciergeOwnerChanged(const std::string& old_owner,
                               const std::string& new_owner);

  // Called when the vm_concierge D-Bus service becomes available.
  void VmConciergeAvailable(bool is_available);

  // Stops all running VMs if the vm_concierge D-Bus service is available.
  void MaybeStopAllVms();

  // Writes the PID of the browser to a file for the crash reporter to read in
  // preparation for the killing the browser.
  void WriteBrowserPidFile(base::FilePath path);

  // Invoked to update |use_long_kill_timeout_| after checking
  // 'SessionManagerUseLongKillTimeout' feature.
  void OnLongKillTimeoutEnabled(std::optional<bool> enabled);

  // Invoked to update |liveness_check_enabled_| after checking
  // the 'SessionManagerLivenessCheck' feature.
  void OnLivenessCheckEnabled(std::optional<bool> enabled);

  // Called on timeout for the SIGABRT by AbortBrowserForHang().
  void OnAbortTimedOut();
  // Called on timeout for the SIGKILL by AbortBrowserForHang().
  void OnSigkillTimedOut();

  std::unique_ptr<BrowserJobInterface> browser_;
  std::optional<base::FilePath> chrome_mount_ns_path_;
  base::TimeTicks last_browser_restart_time_;
  bool exit_on_child_done_ = false;
  const base::TimeDelta kill_timeout_;

  scoped_refptr<dbus::Bus> bus_;
  const std::string match_rule_;
  // These proxies are owned by |bus_|.
  dbus::ObjectProxy* screen_lock_dbus_proxy_ = nullptr;
  dbus::ObjectProxy* powerd_dbus_proxy_ = nullptr;
  dbus::ObjectProxy* vm_concierge_dbus_proxy_ = nullptr;
  dbus::ObjectProxy* debugd_dbus_proxy_ = nullptr;
#if USE_ARC_ADB_SIDELOADING
  dbus::ObjectProxy* boot_lockbox_dbus_proxy_ = nullptr;
#endif
  dbus::ObjectProxy* fwmp_dbus_proxy_ = nullptr;

  // True when the vm_concierge service is available.
  bool vm_concierge_available_ = false;

  LoginMetrics* login_metrics_;  // Owned by the caller.
  SystemUtils* system_;          // Owned by the caller.

  std::unique_ptr<NssUtil> nss_;
  PolicyKey owner_key_;
  KeyGenerator key_gen_;
  DeviceIdentifierGenerator device_identifier_generator_;
  CrossystemImpl crossystem_;
  VpdProcessImpl vpd_process_;
  std::unique_ptr<ContainerManagerInterface> android_container_;
  InstallAttributesReader install_attributes_reader_;
  std::unique_ptr<LivenessChecker> liveness_checker_;
  const bool enable_browser_abort_on_hang_;
  const base::TimeDelta liveness_checking_interval_;
  base::FilePath aborted_browser_pid_path_;
  base::FilePath shutdown_browser_pid_path_;

  // Holds pointers to nss_, key_gen_, this. Shares system_, login_metrics_.
  std::unique_ptr<SessionManagerInterface> impl_;

  // Aborting flow triggered by AbortBrowserForHang is as follows:
  // First, send SIGABRT to the browser process.
  //   - If the browser is terminated expectedly, HandleExit is called.
  //     The aborting is completed here.
  // If the browser is not terminated on timeout, send SIGKILL to all chrome
  // processes.
  //   - If the browser is terminated expectedly, HandleExit is called.
  //     The aborting is completed here.
  // If it still timed out, unfortunately, there's nothing we can do. Leaving
  // the log message.
  // This |abort_timer_| is to handle the time out for HandleExit waiting.
  base::OneShotTimer abort_timer_;

  brillo::AsynchronousSignalHandler signal_handler_;
  std::unique_ptr<ChildExitDispatcher> child_exit_dispatcher_;
  bool shutting_down_ = false;
  ExitCode exit_code_ = SUCCESS;

  std::unique_ptr<ChromeFeaturesServiceClient> chrome_features_service_client_;

  // Whether to use long kill timeout for child jobs. This is updated when
  // chrome starts and check the 'SessionManaagerLongKillTimeout' feature
  // enabled state via ChromeFeaturesService.
  bool use_long_kill_timeout_ = false;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_SESSION_MANAGER_SERVICE_H_
