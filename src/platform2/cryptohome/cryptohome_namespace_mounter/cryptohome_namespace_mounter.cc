// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file gets compiled into the 'cryptohome-namespace-mounter' executable.
// This executable performs an ephemeral mount (for Guest sessions) on behalf of
// cryptohome.
// Eventually, this executable will perform all cryptohome mounts.
// The lifetime of this executable's process matches the lifetime of the mount:
// it's launched by cryptohome when a session is started, and it's
// killed by cryptohome when the session exits.

#include <sysexits.h>

#include <csignal>
#include <map>
#include <memory>
#include <vector>

#include <absl/cleanup/cleanup.h>
#include <base/at_exit.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <brillo/asynchronous_signal_handler.h>
#include <brillo/cryptohome.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/scoped_mount_namespace.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <dbus/cryptohome/dbus-constants.h>

#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/namespace_mounter_ipc.pb.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/mount_constants.h"
#include "cryptohome/storage/mount_helper.h"
#include "cryptohome/storage/mount_utils.h"
#include "cryptohome/username.h"

namespace {

using base::FilePath;
using brillo::cryptohome::home::GetGuestUsername;

std::map<cryptohome::MountType, cryptohome::OutOfProcessMountRequest_MountType>
    kProtobufMountType = {
        // Not mounted.
        {cryptohome::MountType::NONE,
         cryptohome::OutOfProcessMountRequest_MountType_NONE},
        // Encrypted with ecryptfs.
        {cryptohome::MountType::ECRYPTFS,
         cryptohome::OutOfProcessMountRequest_MountType_ECRYPTFS},
        // Encrypted with dircrypto.
        {cryptohome::MountType::DIR_CRYPTO,
         cryptohome::OutOfProcessMountRequest_MountType_DIR_CRYPTO},
        // Encrypted with dm-crypt.
        {cryptohome::MountType::DMCRYPT,
         cryptohome::OutOfProcessMountRequest_MountType_DMCRYPT},
        // Ephemeral mount.
        {cryptohome::MountType::EPHEMERAL,
         cryptohome::OutOfProcessMountRequest_MountType_EPHEMERAL},
        // Vault Migration.
        {cryptohome::MountType::ECRYPTFS_TO_DIR_CRYPTO,
         cryptohome::OutOfProcessMountRequest_MountType_ECRYPTFS_TO_DIR_CRYPTO},
        {cryptohome::MountType::ECRYPTFS_TO_DMCRYPT,
         cryptohome::OutOfProcessMountRequest_MountType_ECRYPTFS_TO_DMCRYPT},
        {cryptohome::MountType::DIR_CRYPTO_TO_DMCRYPT,
         cryptohome::OutOfProcessMountRequest_MountType_DIR_CRYPTO_TO_DMCRYPT},
};

const std::vector<FilePath> kDaemonDirPaths = {
    FilePath("session_manager"), FilePath("shill"), FilePath("shill_logs")};

void CleanUpGuestDaemonDirectories(cryptohome::Platform* platform) {
  FilePath root_home_dir =
      brillo::cryptohome::home::GetRootPath(GetGuestUsername());
  if (!platform->DirectoryExists(root_home_dir)) {
    // No previous Guest sessions have been started, do nothing.
    return;
  }

  for (const FilePath& daemon_path : kDaemonDirPaths) {
    FilePath to_delete = root_home_dir.Append(daemon_path);
    if (platform->DirectoryExists(to_delete)) {
      LOG(INFO) << "Attempting to delete " << to_delete.value();
      if (!platform->DeletePathRecursively(to_delete)) {
        LOG(WARNING) << "Failed to delete " << to_delete.value();
      }
    }
  }
}

bool HandleSignal(base::RepeatingClosure quit_closure,
                  const struct signalfd_siginfo&) {
  VLOG(1) << "Got signal";
  std::move(quit_closure).Run();
  return true;  // unregister the handler
}

}  // namespace

int main(int argc, char** argv) {
  brillo::BaseMessageLoop message_loop;
  message_loop.SetAsCurrent();

  brillo::AsynchronousSignalHandler sig_handler;
  sig_handler.Init();

  brillo::InitLog(brillo::kLogToSyslog);

  cryptohome::ScopedMetricsInitializer metrics;

  cryptohome::OutOfProcessMountRequest request;
  if (!cryptohome::ReadProtobuf(STDIN_FILENO, &request)) {
    LOG(ERROR) << "Failed to read request protobuf";
    return EX_NOINPUT;
  }

  cryptohome::Platform platform;

  // Before performing any mounts, check whether there are any leftover
  // Guest session daemon directories in /home/root/<hashed username>/.
  // See crbug.com/1069501 for details.
  if (request.username() == *GetGuestUsername()) {
    CleanUpGuestDaemonDirectories(&platform);
  }

  std::unique_ptr<brillo::ScopedMountNamespace> ns_mnt;
  if (!request.mount_namespace_path().empty()) {
    // Enter the required mount namespace.
    ns_mnt = brillo::ScopedMountNamespace::CreateFromPath(
        base::FilePath(request.mount_namespace_path()));
    // cryptohome_namespace_mounter will only fail if it cannot enter the
    // existing user session mount namespace. If the namespace doesn't exist
    // cryptohome_namespace_mounter will do the mounts in the root mount
    // namespace. The design here is consistent with the session_manager
    // behavior which will continue in the root mount namespace if the namespace
    // creation is attempted but failed. The failure in the namespace creation
    // is a very rare corner case and the user session will continue in the
    // root mount namespace if that happens.
    if (ns_mnt == nullptr && cryptohome::UserSessionMountNamespaceExists()) {
      cryptohome::ForkAndCrash(
          "cryptohome failed to enter the existing user session mount "
          "namespace");
      return EX_OSERR;
    }
  }

  cryptohome::MountHelper mounter(request.legacy_home(),
                                  request.bind_mount_downloads(), &platform);

  cryptohome::MountError error = cryptohome::MOUNT_ERROR_NONE;
  // Link the user keyring into session keyring to allow request_key() search
  // for ecryptfs mounts.
  if (!platform.SetupProcessKeyring()) {
    LOG(ERROR) << "Failed to set up a process keyring.";
    error = cryptohome::MOUNT_ERROR_SETUP_PROCESS_KEYRING_FAILED;
    return EX_OSERR;
  }

  cryptohome::OutOfProcessMountResponse response;
  bool is_ephemeral =
      request.type() == kProtobufMountType[cryptohome::MountType::EPHEMERAL];

  absl::Cleanup unmount_on_exit = [&mounter]() { mounter.UnmountAll(); };

  if (is_ephemeral) {
    cryptohome::ReportTimerStart(cryptohome::kPerformEphemeralMountTimer);
    cryptohome::StorageStatus status = mounter.PerformEphemeralMount(
        cryptohome::Username(request.username()),
        base::FilePath(request.ephemeral_loop_device()));
    if (status.ok()) {
      error = cryptohome::MOUNT_ERROR_NONE;
    } else {
      error = status->error();
    }

    cryptohome::ReportTimerStop(cryptohome::kPerformEphemeralMountTimer);
  } else {
    cryptohome::MountType mount_type =
        static_cast<cryptohome::MountType>(request.type());

    cryptohome::ReportTimerStart(cryptohome::kPerformMountTimer);
    cryptohome::StorageStatus status = mounter.PerformMount(
        mount_type, cryptohome::Username(request.username()),
        request.fek_signature(), request.fnek_signature());
    if (status.ok()) {
      error = cryptohome::MOUNT_ERROR_NONE;
    } else {
      error = status->error();
    }

    cryptohome::ReportTimerStop(cryptohome::kPerformMountTimer);
  }

  for (const auto& path : mounter.MountedPaths()) {
    response.add_paths(path.value());
  }

  response.set_mount_error(static_cast<uint32_t>(error));
  if (!cryptohome::WriteProtobuf(STDOUT_FILENO, response)) {
    cryptohome::ForkAndCrash("Failed to write response protobuf");
    return EX_OSERR;
  }

  if (error != cryptohome::MOUNT_ERROR_NONE) {
    return EX_SOFTWARE;
  }

  base::RunLoop run_loop;

  // |STDIN_FILENO| is the read end of a pipe whose write end is a file
  // descriptor in 'cryptohomed'. |WatchReadable()| will execute the callback
  // when |STDIN_FILENO| can be read without blocking, or when there is a pipe
  // error. The code does not need to read any more input from 'cryptohomed' at
  // this point so the only expected event on the pipe is the write end of the
  // pipe being closed because of a 'cryptohomed' crash.
  // The resulting behavior is that the code will quit the run loop, clean up
  // the mount, and exit if 'cryptohomed' crashes.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher =
      base::FileDescriptorWatcher::WatchReadable(STDIN_FILENO,
                                                 run_loop.QuitClosure());

  // Quit the run loop when signalled.
  sig_handler.RegisterHandler(
      SIGTERM, base::BindRepeating(&HandleSignal, run_loop.QuitClosure()));

  run_loop.Run();

  // |unmount_on_exit| will clean up the mount now.
  return EX_OK;
}
