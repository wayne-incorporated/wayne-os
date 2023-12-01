// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/userdb_utils.h>
#include <fcntl.h>
#include <libminijail.h>
#include <linux/vtpm_proxy.h>
#include <scoped_minijail.h>
#include <selinux/restorecon.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include "tpm2-simulator/constants.h"
#include "tpm2-simulator/simulator.h"
#include "tpm2-simulator/tpm_nvchip_utils.h"

namespace {
constexpr char kSimulatorSeccompPath[] =
    "/usr/share/policy/tpm2-simulator.policy";
constexpr char kVtpmxPath[] = "/dev/vtpmx";
constexpr char kDevTpmPathPrefix[] = "/dev/tpm";
constexpr size_t kMaxCommandSize = 4096;
constexpr size_t kHeaderSize = 10;

base::ScopedFD RegisterVTPM(base::FilePath* tpm_path, bool is_tpm2) {
  struct vtpm_proxy_new_dev new_dev = {};
  if (is_tpm2) {
    new_dev.flags = VTPM_PROXY_FLAG_TPM2;
  }
  base::ScopedFD vtpmx_fd(HANDLE_EINTR(open(kVtpmxPath, O_RDWR | O_CLOEXEC)));
  if (!vtpmx_fd.is_valid()) {
    return vtpmx_fd;
  }
  if (ioctl(vtpmx_fd.get(), VTPM_PROXY_IOC_NEW_DEV, &new_dev) < 0) {
    PLOG(ERROR) << "Create vTPM failed.";
    // return an invalid FD.
    return {};
  }
  *tpm_path =
      base::FilePath(kDevTpmPathPrefix + std::to_string(new_dev.tpm_num));
  LOG(INFO) << "Create TPM at: /dev/tpm" << new_dev.tpm_num;
  return base::ScopedFD(new_dev.fd);
}

void InitMinijailSandbox() {
  ScopedMinijail j(minijail_new());
  minijail_no_new_privs(j.get());
  minijail_set_seccomp_filter_tsync(j.get());
  minijail_parse_seccomp_filters(j.get(), kSimulatorSeccompPath);
  minijail_use_seccomp_filter(j.get());
  minijail_change_user(j.get(), tpm2_simulator::kSimulatorUser);
  minijail_change_group(j.get(), tpm2_simulator::kSimulatorGroup);
  minijail_inherit_usergroups(j.get());
  minijail_enter(j.get());
}

}  // namespace

namespace tpm2_simulator {

SimulatorDaemon::SimulatorDaemon(TpmExecutor* tpm_executor)
    : tpm_executor_(tpm_executor) {}

int SimulatorDaemon::OnInit() {
  CHECK(tpm_executor_);
  int exit_code = Daemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;
  if (!MountAndEnterNVChip()) {
    LOG(ERROR) << "Failed to mount and enter the NVChip.";
    return EX_OSERR;
  }
  tpm_executor_->InitializeVTPM();
  if (!CorrectWorkingDirectoryFilesOwner()) {
    LOG(ERROR) << "Failed to correct working directory owner.";
    return EX_OSERR;
  }
  base::FilePath tpm_path;
  command_fd_ = RegisterVTPM(&tpm_path, tpm_executor_->IsTPM2());
  if (!command_fd_.is_valid()) {
    LOG(ERROR) << "Failed to register vTPM.";
    return EX_OSERR;
  }
  command_fd_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      command_fd_.get(),
      base::BindRepeating(&SimulatorDaemon::OnCommand, base::Unretained(this)));
  tpm_watcher_.reset(new base::FilePathWatcher);
  tpm_watcher_->Watch(tpm_path, base::FilePathWatcher::Type::kNonRecursive,
                      base::BindRepeating(&SimulatorDaemon::OnTpmPathChange,
                                          base::Unretained(this)));
  return EX_OK;
}

void SimulatorDaemon::OnCommand() {
  CHECK(tpm_executor_);
  char buffer[kMaxCommandSize];
  do {
    std::string request;
    remain_request_.swap(request);

    // Read request header.
    while (kHeaderSize > request.size()) {
      ssize_t size =
          HANDLE_EINTR(read(command_fd_.get(), buffer, kMaxCommandSize));
      CHECK_GE(size, 0);
      request.append(buffer, size);
    }

    const uint32_t command_size = tpm_executor_->GetCommandSize(request);

    // Read request body.
    while (command_size > request.size()) {
      ssize_t size =
          HANDLE_EINTR(read(command_fd_.get(), buffer, kMaxCommandSize));
      CHECK_GE(size, 0);
      request.append(buffer, size);
    }

    // Trim request.
    if (command_size < request.size()) {
      remain_request_ = request.substr(command_size);
      request.resize(command_size);
    }

    // Run command.
    std::string response = tpm_executor_->RunCommand(request);

    // Write response.
    if (!base::WriteFileDescriptor(command_fd_.get(), response)) {
      PLOG(ERROR) << "WriteFileDescriptor failed.";
    }
  } while (!remain_request_.empty());
}

void SimulatorDaemon::OnTpmPathChange(const base::FilePath& path, bool error) {
  if (error) {
    LOG(ERROR) << "Got error while hearing about change to " << path.value();
    return;
  }
  if (!initialized_ && base::PathExists(path)) {
    if (HANDLE_EINTR(selinux_restorecon(path.value().c_str(), 0)) < 0) {
      PLOG(ERROR) << "restorecon(" << path.value() << ") failed";
    }

    LOG(INFO) << "vTPM initialized: " << path.value();
    tpm_watcher_.reset();
    initialized_ = true;
    if (sigstop_on_initialized_) {
      // Raise the SIGSTOP, so upstart would know the initialization process had
      // been finished.
      raise(SIGSTOP);
    }
    // Initialize the minijail.
    InitMinijailSandbox();
  }
}

}  // namespace tpm2_simulator
