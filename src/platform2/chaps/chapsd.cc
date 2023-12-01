// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is the Chaps daemon. It handles calls from multiple processes via D-Bus.
//

#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/synchronization/lock.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/platform_thread.h>
#include <base/threading/thread.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec-foundation/profiling/profiling.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "chaps/chaps_adaptor.h"
#include "chaps/chaps_factory_impl.h"
#include "chaps/chaps_service.h"
#include "chaps/chaps_utility.h"
#include "chaps/dbus_bindings/constants.h"
#include "chaps/platform_globals.h"
#include "chaps/slot_manager_impl.h"

using base::AutoLock;
using base::FilePath;
using base::Lock;
using base::PlatformThread;
using base::PlatformThreadHandle;
using base::WaitableEvent;
using chaps::kPersistentLogLevelPath;
using std::string;

namespace {

void MaskSignals() {
  sigset_t signal_mask;
  CHECK_EQ(0, sigemptyset(&signal_mask));
  for (int signal : {SIGTERM, SIGINT, SIGHUP}) {
    CHECK_EQ(0, sigaddset(&signal_mask, signal));
  }
  CHECK_EQ(0, sigprocmask(SIG_BLOCK, &signal_mask, nullptr));
}

void SetProcessUserAndGroup(const char* user_name, const char* group_name) {
  // Make the umask more restrictive: u + rwx, g + rx.
  umask(0027);

  ScopedMinijail j(minijail_new());
  minijail_change_user(j.get(), user_name);
  minijail_change_group(j.get(), group_name);
  minijail_inherit_usergroups(j.get());
  minijail_no_new_privs(j.get());
  minijail_enter(j.get());
}

}  // namespace

namespace chaps {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon(const std::string& srk_auth_data, bool auto_load_system_token)
      : DBusServiceDaemon(kChapsServiceName),
        srk_auth_data_(srk_auth_data),
        auto_load_system_token_(auto_load_system_token) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override {
    // adaptor_ contains a pointer to service_
    adaptor_.reset();

    // service_ contains a pointer to slot_manager_
    service_.reset();

    // Destructor of slot_manager_ will use hwsec_
    slot_manager_.reset();

    hwsec_.reset();

    hwsec_factory_.reset();

    factory_.reset();
    // Both slot_manager_ and factory_ contains a pointer to chaps_metrics_
    chaps_metrics_.reset();
  }

 protected:
  int OnInit() override {
    hwsec_factory_ = std::make_unique<hwsec::FactoryImpl>();
    hwsec_ = hwsec_factory_->GetChapsFrontend();

    chaps_metrics_.reset(new ChapsMetrics);
    factory_.reset(new ChapsFactoryImpl(chaps_metrics_.get()));
    system_shutdown_blocker_.reset(new SystemShutdownBlocker(
        base::SingleThreadTaskRunner::GetCurrentDefault()));
    slot_manager_.reset(new SlotManagerImpl(
        factory_.get(), hwsec_.get(), auto_load_system_token_,
        system_shutdown_blocker_.get(), chaps_metrics_.get()));
    service_.reset(new ChapsServiceImpl(slot_manager_.get()));

    // Initialize the slot manager.
    if (!slot_manager_->Init()) {
      LOG(FATAL) << "Slot initialization failed.";
    }

    // Now we can export D-Bus objects.
    int return_code = DBusServiceDaemon::OnInit();
    if (return_code != EX_OK)
      return return_code;

    RegisterHandler(SIGTERM, base::BindRepeating(&Daemon::ShutdownSignalHandler,
                                                 base::Unretained(this)));
    RegisterHandler(SIGINT, base::BindRepeating(&Daemon::ShutdownSignalHandler,
                                                base::Unretained(this)));

    return EX_OK;
  }

  void OnShutdown(int* exit_code) override {
    DBusServiceDaemon::OnShutdown(exit_code);
  }

  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_.reset(new ChapsAdaptor(bus_, service_.get(), slot_manager_.get()));
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed", true));
  }

 private:
  // Mimicks |brillo::Daemon::Shutdown| but also logs the incoming signal.
  // TODO(https://crbug.com/844537): Remove when root cause of disappearing
  // system token certificates is found.
  bool ShutdownSignalHandler(const signalfd_siginfo& info) {
    // Trigger daemon shutdown, because the signal handler replaces the
    // original signal handler from |brillo::Daemon|.
    LOG(INFO) << "Chaps exit triggered by signal " << info.ssi_signo << ".";
    Quit();
    return true;  // Unregister the signal handler.
  }

  std::string srk_auth_data_;
  bool auto_load_system_token_;

  // The object to generate the other frontends.
  std::unique_ptr<hwsec::Factory> hwsec_factory_;
  // The object for accessing the HWSec related functions.
  std::unique_ptr<const hwsec::ChapsFrontend> hwsec_;

  std::unique_ptr<ChapsMetrics> chaps_metrics_;
  std::unique_ptr<ChapsFactory> factory_;
  std::unique_ptr<SystemShutdownBlocker> system_shutdown_blocker_;
  std::unique_ptr<SlotManagerImpl> slot_manager_;
  std::unique_ptr<ChapsInterface> service_;
  std::unique_ptr<ChapsAdaptor> adaptor_;
};

}  // namespace chaps

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  chaps::ScopedOpenSSL openssl;

  if (!cl->HasSwitch("v")) {
    // Read persistent file for log level if no command line verbositity level
    // is specified.
    std::string log_level;
    bool success =
        base::ReadFileToString(FilePath(kPersistentLogLevelPath), &log_level);
    if (success) {
      int log_level_int;
      if (base::StringToInt(log_level, &log_level_int))
        logging::SetMinLogLevel(log_level_int);
      int delete_success = base::DeleteFile(FilePath(kPersistentLogLevelPath));
      VLOG_IF(2, !delete_success) << "Failed to delete log level file.";
    }
  }

  LOG(INFO) << "Starting PKCS #11 services.";
  // Set TPM metrics client ID.
  hwsec_foundation::SetTpmMetricsClientID(
      hwsec_foundation::TpmMetricsClientID::kChaps);
  // Run as 'chaps'.
  SetProcessUserAndGroup(chaps::kChapsdProcessUser, chaps::kChapsdProcessGroup);
  // Determine SRK authorization data from the command line.
  string srk_auth_data;
  if (cl->HasSwitch("srk_password")) {
    srk_auth_data = cl->GetSwitchValueASCII("srk_password");
  } else if (cl->HasSwitch("srk_zeros")) {
    int zero_count = 0;
    if (base::StringToInt(cl->GetSwitchValueASCII("srk_zeros"), &zero_count)) {
      srk_auth_data = string(zero_count, 0);
    } else {
      LOG(WARNING) << "Invalid value for srk_zeros: using empty string.";
    }
  }
  bool auto_load_system_token = cl->HasSwitch("auto_load_system_token");
  // Mask signals handled by the daemon thread. This makes sure we
  // won't handle shutdown signals on one of the other threads spawned
  // below.
  MaskSignals();
  LOG(INFO) << "Starting D-Bus dispatcher.";

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  chaps::Daemon(srk_auth_data, auto_load_system_token).Run();
  return 0;
}
