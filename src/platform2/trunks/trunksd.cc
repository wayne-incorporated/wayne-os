// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>
#include <sysexits.h>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/threading/thread.h>
#include <brillo/syslog_logging.h>
#include <brillo/userdb_utils.h>
#include <libhwsec-foundation/profiling/profiling.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "trunks/background_command_transceiver.h"
#include "trunks/power_manager.h"
#include "trunks/resilience/write_error_tracker_impl.h"
#include "trunks/resource_manager.h"
#include "trunks/tpm_handle.h"
#include "trunks/trunks_dbus_service.h"
#include "trunks/trunks_factory_impl.h"
#include "trunks/trunks_ftdi_spi.h"

namespace {

namespace switches {

constexpr char kNoCloseOnDaemonize[] = "noclose";
constexpr char kNoDaemonize[] = "nodaemonize";
constexpr char kLogToStderr[] = "log_to_stderr";

}  // namespace switches

const uid_t kRootUID = 0;
const char kTrunksUser[] = "trunks";
const char kTrunksGroup[] = "trunks";
const char kTrunksSeccompPath[] = "/usr/share/policy/trunksd-seccomp.policy";
const char kBackgroundThreadName[] = "trunksd_background_thread";
const char kWriteErrorTrackingPath[] = "/run/trunks/last-write-error";

void InitMinijailSandbox() {
  uid_t trunks_uid;
  gid_t trunks_gid;
  CHECK(brillo::userdb::GetUserInfo(kTrunksUser, &trunks_uid, &trunks_gid))
      << "Error getting trunks uid and gid.";
  CHECK_EQ(getuid(), kRootUID) << "trunksd not initialized as root.";

  ScopedMinijail j(minijail_new());
  minijail_set_seccomp_filter_tsync(j.get());
  minijail_no_new_privs(j.get());
  minijail_bind(j.get(), "/run/trunks", "/run/trunks", 1);
  minijail_use_seccomp_filter(j.get());
  minijail_parse_seccomp_filters(j.get(), kTrunksSeccompPath);
  minijail_change_user(j.get(), kTrunksUser);
  minijail_change_group(j.get(), kTrunksGroup);
  minijail_enter(j.get());

  CHECK_EQ(getuid(), trunks_uid)
      << "trunksd was not able to drop user privilege.";
  CHECK_EQ(getgid(), trunks_gid)
      << "trunksd was not able to drop group privilege.";
}

// Add the signals, for which the handlers are added by brillo::Daemon
// to the blocked mask.
void MaskSignals() {
  sigset_t signal_mask;
  CHECK_EQ(0, sigemptyset(&signal_mask));
  for (int signal : {SIGTERM, SIGINT, SIGHUP}) {
    CHECK_EQ(0, sigaddset(&signal_mask, signal));
  }
  CHECK_EQ(0, sigprocmask(SIG_BLOCK, &signal_mask, nullptr));
  VLOG(2) << "Signal mask set.";
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch(switches::kLogToStderr)) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  bool noclose = cl->HasSwitch(switches::kNoCloseOnDaemonize);
  bool daemonize = !cl->HasSwitch(switches::kNoDaemonize);

  trunks::WriteErrorTrackerImpl write_error_tracker(kWriteErrorTrackingPath);

  // Chain together command transceivers:
  //   [IPC] --> BackgroundCommandTransceiver
  //         --> ResourceManager
  //         --> TpmHandle
  //         --> [TPM]
  trunks::CommandTransceiver* low_level_transceiver = nullptr;
  if (cl->HasSwitch("ftdi")) {
    LOG(INFO) << "Sending commands to FTDI SPI.";
    low_level_transceiver = new trunks::TrunksFtdiSpi();
  } else {
    low_level_transceiver = new trunks::TpmHandle(write_error_tracker);
  }
  CHECK(low_level_transceiver->Init())
      << "Error initializing TPM communication.";

  // Upstart would know trunksd is ready after trunksd daemonized.
  if (daemonize) {
    PLOG_IF(FATAL, daemon(0, noclose) == -1) << "Failed to daemonize";
  }

  // Create a service instance so objects like AtExitManager exist.
  trunks::TrunksDBusService service(write_error_tracker);

  // This needs to be *after* opening the TPM handle and *before* starting the
  // background thread.
  InitMinijailSandbox();
  // Make sure signals handled by the server are blocked in all threads,
  // otherwise the process still dies.
  // This needs to be *before* starting the background thread.
  MaskSignals();
  base::Thread background_thread(kBackgroundThreadName);
  CHECK(background_thread.Start()) << "Failed to start background thread.";
  trunks::TrunksFactoryImpl factory(low_level_transceiver);
  CHECK(factory.Initialize()) << "Failed to initialize trunks factory.";
  trunks::ResourceManager resource_manager(factory, low_level_transceiver);
  background_thread.task_runner()->PostNonNestableTask(
      FROM_HERE, base::BindOnce(&trunks::ResourceManager::Initialize,
                                base::Unretained(&resource_manager)));
  trunks::BackgroundCommandTransceiver background_transceiver(
      &resource_manager, background_thread.task_runner());
  service.set_transceiver(&background_transceiver);
  trunks::PowerManager power_manager(&resource_manager,
                                     background_thread.task_runner());
  service.set_power_manager(&power_manager);
  LOG(INFO) << "Trunks service started.";

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  int exit_code = service.Run();
  if (!write_error_tracker.Write()) {
    LOG(WARNING) << "Failed to write the write errorno.";
  }

  // Need to stop the background thread before destroying ResourceManager
  // and PowerManager. Otherwise, a task posted by BackgroundCommandTransceiver
  // may attempt to access those destroyed objects.
  background_thread.Stop();
  return exit_code;
}
