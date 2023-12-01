// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/krb5_jail_wrapper.h"

#include <vector>

#include <sys/wait.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/process/process.h>

namespace kerberos {
namespace {

constexpr char kerberosd_exec[] = "kerberosd-exec";

// Timeout for child processes.
constexpr base::TimeDelta kProcessExitTimeout = base::Minutes(3);

bool g_change_user_disabled_for_testing = false;

// Read/write for owner, read for group.
constexpr int kFileMode_rw_r = base::FILE_PERMISSION_READ_BY_USER |
                               base::FILE_PERMISSION_WRITE_BY_USER |
                               base::FILE_PERMISSION_READ_BY_GROUP;

// Forks a process to a parent and a jailed child process and manages a pipe for
// data transfer from the child to the parent.
class MinijailForker {
 public:
  // Forks the process into a parent and a child process and puts the child in a
  // jail because it was naughty. Also sets up a pipe to send data from the
  // child to the parent.
  MinijailForker();
  ~MinijailForker();

  // Returns true if the current process is the child process.
  // Returns false for the parent process.
  bool IsChild() const { return child_pid_ == 0; }

  //
  // Child interface. DCHECKs IsChild().
  //

  // Writes the |error| status to the data pipe.
  void Child_WriteError(ErrorType error);

  // Writes the |tgt_status| code to the data pipe.
  void Child_WriteTgtStatus(const Krb5Interface::TgtStatus& tgt_status);

  // Writes the config validation |error_info| to the data pipe.
  void Child_WriteErrorInfo(const ConfigErrorInfo& error_info);

  // Exits the process with code 0 if no error occurred and 1 otherwise.
  void Child_Exit();

  //
  // Parent interface. DCHECKs !IsChild().
  //

  // Waits for the child process to exit. Sets |error_| to true in case the
  // child didn't exit with status 0.
  void Parent_Wait();

  // Reads an error status from the data pipe.
  ErrorType Parent_ReadError();

  // Reads a TGT status from the data pipe.
  Krb5Interface::TgtStatus Parent_ReadTgtStatus();

  // Reads config validation error info from the data pipe.
  ConfigErrorInfo Parent_ReadErrorInfo();

 private:
  // Writes |data| of size |data_size| to the data pipe. Sets |error_| on error.
  // Note: Assumes that all data fits into the pipe buffer. If the pipe buffer
  // is exceeded, |error_| is set to true.
  void Child_Write(const void* data, size_t data_size);

  // Reads |data| of size |data_size| from the data pipe. |data| must be big
  // enough to hold |data_size| bytes. Sets |error_| on error.
  void Parent_Read(void* data, size_t data_size);

  ScopedMinijail jail_;
  base::ScopedFD pipe_read_end_;
  base::ScopedFD pipe_write_end_;
  pid_t child_pid_ = -1;
  bool error_ = false;
};

MinijailForker::MinijailForker() : jail_(minijail_new()) {
  // Create pipes for data transfer from child to parent.
  int pipe_fd[2];
  if (!base::CreateLocalNonBlockingPipe(pipe_fd)) {
    LOG(ERROR) << "Failed to create pipe";
    error_ = true;
    return;
  }
  pipe_read_end_.reset(pipe_fd[0]);
  pipe_write_end_.reset(pipe_fd[1]);

  // Change uid to kerberosd-exec.
  if (!g_change_user_disabled_for_testing)
    CHECK_EQ(0, minijail_change_user(jail_.get(), kerberosd_exec));

  // Required since we don't have the caps to wipe supplementary groups.
  minijail_keep_supplementary_gids(jail_.get());

  // Fork the process.
  child_pid_ = minijail_fork(jail_.get());
  if (child_pid_ < 0) {
    PLOG(ERROR) << "Failed to fork process and enter jail";
    error_ = true;
    return;
  }
}

MinijailForker::~MinijailForker() = default;

void MinijailForker::Child_WriteError(ErrorType error) {
  Child_Write(&error, sizeof(error));
}

void MinijailForker::Child_WriteTgtStatus(
    const Krb5Interface::TgtStatus& tgt_status) {
  Child_Write(&tgt_status.validity_seconds,
              sizeof(tgt_status.validity_seconds));
  Child_Write(&tgt_status.renewal_seconds, sizeof(tgt_status.renewal_seconds));
}

void MinijailForker::Child_WriteErrorInfo(const ConfigErrorInfo& error_info) {
  std::vector<uint8_t> buffer(error_info.ByteSizeLong());
  CHECK(error_info.SerializeToArray(buffer.data(), buffer.size()));
  int buffer_size = static_cast<int>(buffer.size());
  Child_Write(&buffer_size, sizeof(buffer_size));
  Child_Write(buffer.data(), buffer.size());
}

void MinijailForker::Child_Exit() {
  DCHECK(IsChild());
  exit(error_ ? 1 : 0);
}

void MinijailForker::Parent_Wait() {
  DCHECK(!IsChild());

  auto process = base::Process::Open(child_pid_);
  int exit_code = -1;
  if (!process.WaitForExitWithTimeout(kProcessExitTimeout, &exit_code)) {
    LOG(ERROR) << "Child process timed out";
    process.Terminate(-1 /* exit_code */, false /* wait */);
    error_ = true;
    return;
  }

  if (exit_code != 0) {
    LOG(ERROR) << "Child process exited with code " << exit_code;
    error_ = true;
  }
}

ErrorType MinijailForker::Parent_ReadError() {
  // Handle internal errors, don't try to read ErrorType, it might block.
  ErrorType error = ERROR_JAIL_FAILURE;
  if (error_)
    return error;

  Parent_Read(&error, sizeof(error));
  return error_ ? ERROR_JAIL_FAILURE : error;
}

Krb5Interface::TgtStatus MinijailForker::Parent_ReadTgtStatus() {
  // Handle internal errors, don't try to read the TGT status, it might block.
  Krb5Interface::TgtStatus tgt_status;
  if (error_)
    return tgt_status;

  Parent_Read(&tgt_status.validity_seconds,
              sizeof(tgt_status.validity_seconds));
  Parent_Read(&tgt_status.renewal_seconds, sizeof(tgt_status.renewal_seconds));
  return tgt_status;
}

ConfigErrorInfo MinijailForker::Parent_ReadErrorInfo() {
  // Handle internal errors, don't try to read the error info, it might block.
  ConfigErrorInfo error_info;
  if (error_)
    return error_info;

  int buffer_size = 0;
  Parent_Read(&buffer_size, sizeof(buffer_size));
  if (buffer_size == 0)
    return error_info;

  std::vector<uint8_t> buffer;
  buffer.resize(buffer_size);
  Parent_Read(buffer.data(), buffer_size);
  error_info.ParseFromArray(buffer.data(), buffer_size);
  return error_info;
}

void MinijailForker::Child_Write(const void* data, size_t data_size) {
  DCHECK(IsChild());
  if (!base::WriteFileDescriptor(
          pipe_write_end_.get(),
          base::make_span(static_cast<const uint8_t*>(data), data_size))) {
    LOG(ERROR) << "Failed to write " << data_size << " bytes";
    error_ = true;
  }
}

void MinijailForker::Parent_Read(void* data, size_t data_size) {
  DCHECK(!IsChild());
  if (HANDLE_EINTR(read(pipe_read_end_.get(), data, data_size)) !=
      static_cast<int>(data_size)) {
    LOG(ERROR) << "Failed to read " << data_size << " bytes";
    error_ = true;
  }
}

// If |error| is ERROR_NONE, gives TGT at |krb5cc_path| group read permission
// (for the kerberosd group), so that the kerberosd user can read it.
void SetTgtFilePermissions(const base::FilePath& krb5cc_path, ErrorType error) {
  if (error == ERROR_NONE)
    CHECK(base::SetPosixFilePermissions(krb5cc_path, kFileMode_rw_r));
}

}  // namespace

Krb5JailWrapper::Krb5JailWrapper(std::unique_ptr<Krb5Interface> krb5)
    : krb5_(std::move(krb5)) {}

Krb5JailWrapper::~Krb5JailWrapper() = default;

ErrorType Krb5JailWrapper::AcquireTgt(const std::string& principal_name,
                                      const std::string& password,
                                      const base::FilePath& krb5cc_path,
                                      const base::FilePath& krb5conf_path) {
  MinijailForker forker;

  if (forker.IsChild()) {
    ErrorType error =
        krb5_->AcquireTgt(principal_name, password, krb5cc_path, krb5conf_path);
    SetTgtFilePermissions(krb5cc_path, error);
    forker.Child_WriteError(error);
    forker.Child_Exit();
  }

  forker.Parent_Wait();
  return forker.Parent_ReadError();
}

ErrorType Krb5JailWrapper::RenewTgt(const std::string& principal_name,
                                    const base::FilePath& krb5cc_path,
                                    const base::FilePath& krb5conf_path) {
  MinijailForker forker;

  if (forker.IsChild()) {
    ErrorType error =
        krb5_->RenewTgt(principal_name, krb5cc_path, krb5conf_path);
    SetTgtFilePermissions(krb5cc_path, error);
    forker.Child_WriteError(error);
    forker.Child_Exit();
  }

  forker.Parent_Wait();
  return forker.Parent_ReadError();
}

ErrorType Krb5JailWrapper::GetTgtStatus(const base::FilePath& krb5cc_path,
                                        Krb5Interface::TgtStatus* status) {
  MinijailForker forker;

  if (forker.IsChild()) {
    ErrorType error = krb5_->GetTgtStatus(krb5cc_path, status);
    forker.Child_WriteTgtStatus(*status);
    forker.Child_WriteError(error);
    forker.Child_Exit();
  }

  forker.Parent_Wait();
  *status = forker.Parent_ReadTgtStatus();
  return forker.Parent_ReadError();
}

ErrorType Krb5JailWrapper::ValidateConfig(const std::string& krb5conf,
                                          ConfigErrorInfo* error_info) {
  MinijailForker forker;

  if (forker.IsChild()) {
    ErrorType error = krb5_->ValidateConfig(krb5conf, error_info);
    forker.Child_WriteErrorInfo(*error_info);
    forker.Child_WriteError(error);
    forker.Child_Exit();
  }

  forker.Parent_Wait();
  *error_info = forker.Parent_ReadErrorInfo();
  return forker.Parent_ReadError();
}

// static
void Krb5JailWrapper::DisableChangeUserForTesting(bool disabled) {
  g_change_user_disabled_for_testing = disabled;
}

}  // namespace kerberos
