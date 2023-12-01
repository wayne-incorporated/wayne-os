// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/dbus_service.h"

#include <cstdlib>
#include <string>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <chaps/pkcs11/cryptoki.h>
#include <brillo/syslog_logging.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/profiling/profiling.h>
#include <libhwsec-foundation/tpm_error/tpm_error_uma_reporter.h>
#include <openssl/evp.h>

#include "cryptohome/cleanup/disk_cleanup.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/userdataauth.h"

namespace switches {
// Keeps std* open for debugging.
static const char* kNoCloseOnDaemonize = "noclose";
static const char* kNoLegacyMount = "nolegacymount";
static const char* kNoDownloadsBindMount = "no_downloads_bind_mount";
static const char* kDirEncryption = "direncryption";
static const char* kFscryptV2 = "fscrypt_v2";
static const char* kApplicationContainers = "application_containers";
static const char* kNegateFscryptV2ForTest = "negate_fscrypt_v2_for_test";
static const char* kNoDaemonize = "nodaemonize";
static const char* kCleanupThreshold = "cleanup_threshold";
static const char* kAggressiveThreshold = "aggressive_cleanup_threshold";
static const char* kCriticalThreshold = "critical_cleanup_threshold";
static const char* kTargetFreeSpace = "target_free_space";
static const char* kDisableErrorMetrics = "disable_error_metrics";

}  // namespace switches

uint64_t ReadCleanupThreshold(const base::CommandLine* cl,
                              const char* switch_name,
                              uint64_t default_value) {
  std::string value = cl->GetSwitchValueASCII(switch_name);

  if (value.size() == 0) {
    return default_value;
  }

  uint64_t parsed_value;
  if (!base::StringToUint64(value, &parsed_value)) {
    LOG(ERROR) << "Failed to parse " << switch_name << "; using defaults";
    return default_value;
  }

  return parsed_value;
}

int main(int argc, char** argv) {
  // Initialize command line configuration early, as logging will require
  // command line to be initialized
  base::CommandLine::Init(argc, argv);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  // Start profiling.
  hwsec_foundation::SetUpProfiling();

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int noclose = cl->HasSwitch(switches::kNoCloseOnDaemonize);
  bool nolegacymount = cl->HasSwitch(switches::kNoLegacyMount);
  bool nodownloadsbind = cl->HasSwitch(switches::kNoDownloadsBindMount);
  bool direncryption = cl->HasSwitch(switches::kDirEncryption);
  bool fscryptv2 = cl->HasSwitch(switches::kFscryptV2) &&
                   !cl->HasSwitch(switches::kNegateFscryptV2ForTest);
  bool application_containers = cl->HasSwitch(switches::kApplicationContainers);
  bool daemonize = !cl->HasSwitch(switches::kNoDaemonize);
  bool disable_error_metrics = cl->HasSwitch(switches::kDisableErrorMetrics);
  uint64_t cleanup_threshold =
      ReadCleanupThreshold(cl, switches::kCleanupThreshold,
                           cryptohome::kFreeSpaceThresholdToTriggerCleanup);
  uint64_t aggressive_cleanup_threshold = ReadCleanupThreshold(
      cl, switches::kAggressiveThreshold,
      cryptohome::kFreeSpaceThresholdToTriggerAggressiveCleanup);
  uint64_t critical_cleanup_threshold = ReadCleanupThreshold(
      cl, switches::kCriticalThreshold,
      cryptohome::kFreeSpaceThresholdToTriggerCriticalCleanup);
  uint64_t target_free_space = ReadCleanupThreshold(
      cl, switches::kTargetFreeSpace, cryptohome::kTargetFreeSpaceAfterCleanup);

  if (daemonize) {
    PLOG_IF(FATAL, daemon(0, noclose) == -1) << "Failed to daemonize";
  }

  // Initialize OpenSSL.
  OpenSSL_add_all_algorithms();

  // Initialize cryptohome metrics
  // Because mount thread may use metrics after main scope, don't
  // TearDownMetrics after main finished.
  cryptohome::InitializeMetrics();

  if (disable_error_metrics) {
    cryptohome::DisableErrorMetricsReporting();
  }

  // Set TPM metrics client ID.
  hwsec_foundation::SetTpmMetricsClientID(
      hwsec_foundation::TpmMetricsClientID::kCryptohome);

  // Make sure scrypt parameters are correct.
  hwsec_foundation::AssertProductionScryptParams();

  // Note that there's an AtExitManager in the constructor of
  // UserDataAuthDaemon
  cryptohome::UserDataAuthDaemon user_data_auth_daemon;

  // Set options on whether we are going to use legacy mount. See comments on
  // Mount::MountLegacyHome() for more information.
  user_data_auth_daemon.GetUserDataAuth()->set_legacy_mount(!nolegacymount);
  user_data_auth_daemon.GetUserDataAuth()->set_bind_mount_downloads(
      !nodownloadsbind);

  // Set options on whether we are going to use ext4 directory encryption or
  // eCryptfs.
  user_data_auth_daemon.GetUserDataAuth()->set_force_ecryptfs(!direncryption);
  user_data_auth_daemon.GetUserDataAuth()->set_fscrypt_v2(fscryptv2);

  // Set options on whether we are creating application containers for LVM
  // vaults.
  user_data_auth_daemon.GetUserDataAuth()->set_enable_application_containers(
      application_containers);

  // Set automatic cleanup thresholds.
  user_data_auth_daemon.GetUserDataAuth()->set_cleanup_threshold(
      cleanup_threshold);
  user_data_auth_daemon.GetUserDataAuth()->set_aggressive_cleanup_threshold(
      aggressive_cleanup_threshold);
  user_data_auth_daemon.GetUserDataAuth()->set_critical_cleanup_threshold(
      critical_cleanup_threshold);
  user_data_auth_daemon.GetUserDataAuth()->set_target_free_space(
      target_free_space);

  // Note the startup sequence is as following:
  // 1. UserDataAuthDaemon constructor => UserDataAuth constructor
  // 2. UserDataAuthDaemon::OnInit() (called by Daemon::Run())
  // 3. UserDataAuthDaemon::RegisterDBusObjectsAsync() (called by 2.)
  // 4. UserDataAuth::Initialize() (called by 3.)
  // Daemon::OnInit() needs to be called before Initialize(), because
  // Initialize() create threads, and thus mess with Daemon's
  // AsynchronousSignalHandler.

  // Start UserDataAuth daemon if the option is selected
  user_data_auth_daemon.Run();

  // If PKCS #11 was initialized, this will tear it down.
  C_Finalize(NULL);

  return 0;
}
