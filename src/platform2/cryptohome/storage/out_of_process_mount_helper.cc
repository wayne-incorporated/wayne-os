// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/out_of_process_mount_helper.h"

#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sysexits.h>

#include <algorithm>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <absl/cleanup/cleanup.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/cryptohome.h>
#include <brillo/process/process.h>
#include <brillo/secure_blob.h>
#include <chromeos/constants/cryptohome.h>

#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/namespace_mounter_ipc.pb.h"
#include "cryptohome/storage/mount_constants.h"
#include "cryptohome/storage/mount_utils.h"

using base::FilePath;
using base::StringPrintf;

namespace cryptohome {

namespace {

// How long to wait for the out-of-process helper to perform a mount.
//
// Wait up to three seconds for the ephemeral mount to be performed.
//
// Normally, setting up a full ephemeral mount takes about 300 ms, so
// give ourselves a healthy 40x margin.
//
// Certain boards can be very slow on mount operations. Extend the timeout in
// this case to 120s.
constexpr base::TimeDelta kOutOfProcessHelperMountTimeout =
    base::Seconds(USE_SLOW_MOUNT ? 120 : 12);

// How long to wait for the out-of-process helper to exit and be reaped.
//
// Wait one second for the helper to exit and be reaped.
//
// The brillo::Process::Kill() function that takes this timeout does not allow
// for sub-second granularity, and waiting more than one second for the helper
// to exit makes little sense: the helper is designed to clean up and exit
// quickly: it takes about 100 ms to clean up ephemeral mounts.
//
// Certain boards can be very slow on mount operations. Extend the timeout in
// this case to 120s.
constexpr base::TimeDelta kOutOfProcessHelperReapTimeout =
    base::Seconds(USE_SLOW_MOUNT ? 120 : 1);

bool WaitForHelper(int read_from_helper, const base::TimeDelta& timeout) {
  struct pollfd poll_fd = {};
  poll_fd.fd = read_from_helper;
  poll_fd.events = POLLIN;

  // While HANDLE_EINTR will restart the timeout, this happening repeatedly
  // should be exceedingly rare.
  int ret = HANDLE_EINTR(poll(&poll_fd, 1U, timeout.InMilliseconds()));

  if (ret < 0) {
    PLOG(ERROR) << "poll(read_from_helper) failed";
    return false;
  }

  if (ret == 0) {
    LOG(ERROR) << "WaitForHelper timed out";
    return false;
  }

  return (poll_fd.revents & POLLIN) == POLLIN;
}

std::map<MountType, OutOfProcessMountRequest_MountType> kProtobufMountType = {
    // Not mounted.
    {MountType::NONE, OutOfProcessMountRequest_MountType_NONE},
    // Encrypted with ecryptfs.
    {MountType::ECRYPTFS, OutOfProcessMountRequest_MountType_ECRYPTFS},
    // Encrypted with dircrypto.
    {MountType::DIR_CRYPTO, OutOfProcessMountRequest_MountType_DIR_CRYPTO},
    // Encrypted with dmcrpyt.
    {MountType::DMCRYPT, OutOfProcessMountRequest_MountType_DMCRYPT},
    // Ephemeral mount.
    {MountType::EPHEMERAL, OutOfProcessMountRequest_MountType_EPHEMERAL},
    // Vault Migration.
    {MountType::ECRYPTFS_TO_DIR_CRYPTO,
     OutOfProcessMountRequest_MountType_ECRYPTFS_TO_DIR_CRYPTO},
    {MountType::ECRYPTFS_TO_DMCRYPT,
     OutOfProcessMountRequest_MountType_ECRYPTFS_TO_DMCRYPT},
    {MountType::DIR_CRYPTO_TO_DMCRYPT,
     OutOfProcessMountRequest_MountType_DIR_CRYPTO_TO_DMCRYPT},
};

StorageStatus OopErrorCodeToStatus(MountError error) {
  if (error == MOUNT_ERROR_NONE) {
    return StorageStatus::Ok();
  }
  // The error is already reported from OOP, so no need to report it here.
  return StorageStatus::Make(FROM_HERE, "OOP mount failed", error,
                             /*report=*/false);
}

}  // namespace

//  cryptohome_namespace_mounter enters the Chrome mount namespace and mounts
//  the user cryptohome in that mount namespace if the flags are enabled.
//  Chrome mount namespace is created by session_manager. cryptohome knows
//  the path at which this mount namespace is created and uses that path to
//  enter it.
OutOfProcessMountHelper::OutOfProcessMountHelper(bool legacy_home,
                                                 bool bind_mount_downloads,
                                                 Platform* platform)
    : legacy_home_(legacy_home),
      bind_mount_downloads_(bind_mount_downloads),
      platform_(platform),
      username_(),
      write_to_helper_(-1) {}

bool OutOfProcessMountHelper::CanPerformEphemeralMount() const {
  return !helper_process_ || helper_process_->pid() == 0;
}

bool OutOfProcessMountHelper::MountPerformed() const {
  return helper_process_ && helper_process_->pid() > 0;
}

bool OutOfProcessMountHelper::IsPathMounted(const base::FilePath& path) const {
  return mounted_paths_.count(path.value()) > 0;
}

void OutOfProcessMountHelper::KillOutOfProcessHelperIfNecessary() {
  if (helper_process_->pid() == 0) {
    return;
  }

  if (helper_process_->Kill(SIGTERM,
                            kOutOfProcessHelperReapTimeout.InSeconds())) {
    ReportOOPMountCleanupResult(OOPMountCleanupResult::kSuccess);
  } else {
    LOG(ERROR) << "Failed to send SIGTERM to OOP mount helper";

    // If the process didn't exit on SIGTERM, attempt SIGKILL.
    if (helper_process_->Kill(SIGKILL, 0)) {
      // If SIGKILL succeeds (with SIGTERM having failed) log the fact that
      // poking failed.
      ReportOOPMountCleanupResult(OOPMountCleanupResult::kFailedToPoke);
    } else {
      LOG(ERROR) << "Failed to kill OOP mount helper";
      ReportOOPMountCleanupResult(OOPMountCleanupResult::kFailedToKill);
    }
  }

  // Reset the brillo::Process object to close pipe file descriptors.
  helper_process_->Reset(0);
}

StorageStatus OutOfProcessMountHelper::PerformEphemeralMount(
    const Username& username, const base::FilePath& ephemeral_loop_device) {
  OutOfProcessMountRequest request;
  request.set_username(*username);
  request.set_legacy_home(legacy_home_);
  request.set_bind_mount_downloads(bind_mount_downloads_);
  request.set_mount_namespace_path(
      username == brillo::cryptohome::home::GetGuestUsername()
          ? kUserSessionMountNamespacePath
          : "");
  request.set_type(OutOfProcessMountRequest_MountType_EPHEMERAL);
  request.set_ephemeral_loop_device(ephemeral_loop_device.value());

  OutOfProcessMountResponse response;
  if (!LaunchOutOfProcessHelper(request, &response)) {
    return StorageStatus::Make(FROM_HERE, "Failed to launch OOP-mounter",
                               MOUNT_ERROR_FATAL);
  }

  username_ = request.username();
  if (response.paths_size() > 0) {
    for (int i = 0; i < response.paths_size(); i++) {
      mounted_paths_.insert(response.paths(i));
    }
  }

  return OopErrorCodeToStatus(static_cast<MountError>(response.mount_error()));
}

bool OutOfProcessMountHelper::LaunchOutOfProcessHelper(
    const OutOfProcessMountRequest& request,
    OutOfProcessMountResponse* response) {
  std::unique_ptr<brillo::Process> mount_helper =
      platform_->CreateProcessInstance();

  mount_helper->AddArg("/usr/sbin/cryptohome-namespace-mounter");

  mount_helper->RedirectUsingPipe(
      STDIN_FILENO, true /* is_input, from child's perspective */);
  mount_helper->RedirectUsingPipe(
      STDOUT_FILENO, false /* is_input, from child's perspective */);

  if (!mount_helper->Start()) {
    LOG(ERROR) << "Failed to start OOP mount helper";
    ReportOOPMountOperationResult(OOPMountOperationResult::kFailedToStart);
    return false;
  }

  helper_process_ = std::move(mount_helper);
  write_to_helper_ = helper_process_->GetPipe(STDIN_FILENO);
  int read_from_helper = helper_process_->GetPipe(STDOUT_FILENO);

  absl::Cleanup kill_runner_on_exit = [this]() {
    KillOutOfProcessHelperIfNecessary();
  };

  if (!WriteProtobuf(write_to_helper_, request)) {
    LOG(ERROR) << "Failed to write request protobuf";
    ReportOOPMountOperationResult(
        OOPMountOperationResult::kFailedToWriteRequestProtobuf);
    return false;
  }

  // Avoid blocking forever in the read(2) call below by poll(2)-ing the file
  // descriptor with a |kOutOfProcessHelperMountTimeout| long timeout.
  if (!WaitForHelper(read_from_helper, kOutOfProcessHelperMountTimeout)) {
    LOG(ERROR) << "OOP mount helper did not respond in time";
    ReportOOPMountOperationResult(
        OOPMountOperationResult::kHelperProcessTimedOut);
    return false;
  }

  if (!ReadProtobuf(read_from_helper, response)) {
    LOG(ERROR) << "Failed to read response protobuf";
    ReportOOPMountOperationResult(
        OOPMountOperationResult::kFailedToReadResponseProtobuf);
    return false;
  }

  // OOP mount helper started successfully, release the clean-up closure.
  std::move(kill_runner_on_exit).Cancel();

  LOG(INFO) << "OOP mount helper started successfully";
  ReportOOPMountOperationResult(OOPMountOperationResult::kSuccess);
  return true;
}

void OutOfProcessMountHelper::UnmountAll() {
  TearDownExistingMount();
}

bool OutOfProcessMountHelper::TearDownExistingMount() {
  if (!helper_process_) {
    LOG(WARNING) << "Can't tear down mount, OOP mount helper is not running";
    return false;
  }

  // While currently a MountHelper instance is not used for more than one
  // cryptohome mount operation, this function should ensure that the
  // MountHelper instance is left in a state suited to perform subsequent
  // mounts.
  KillOutOfProcessHelperIfNecessary();
  mounted_paths_.clear();
  username_.clear();
  return true;
}

StorageStatus OutOfProcessMountHelper::PerformMount(
    MountType mount_type,
    const Username& username,
    const std::string& fek_signature,
    const std::string& fnek_signature) {
  OutOfProcessMountRequest request;
  request.set_username(*username);
  request.set_bind_mount_downloads(bind_mount_downloads_);
  request.set_legacy_home(legacy_home_);
  request.set_mount_namespace_path(
      IsolateUserSession() ? kUserSessionMountNamespacePath : "");
  request.set_type(kProtobufMountType[mount_type]);
  request.set_fek_signature(fek_signature);
  request.set_fnek_signature(fnek_signature);

  OutOfProcessMountResponse response;
  if (!LaunchOutOfProcessHelper(request, &response)) {
    return StorageStatus::Make(FROM_HERE, "Failed to launch OOP-mounter",
                               MOUNT_ERROR_FATAL);
  }

  username_ = request.username();
  if (response.paths_size() > 0) {
    for (int i = 0; i < response.paths_size(); i++) {
      mounted_paths_.insert(response.paths(i));
    }
  }

  return OopErrorCodeToStatus(static_cast<MountError>(response.mount_error()));
}

}  // namespace cryptohome
