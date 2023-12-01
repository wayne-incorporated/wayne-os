// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/executor/utils/fake_process_control.h"

#include <csignal>
#include <string>
#include <utility>

#include <base/files/platform_file.h>
#include <base/files/scoped_file.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/system/handle.h>

namespace diagnostics {

FakeProcessControl::FakeProcessControl() {
  if (!temp_dir_.CreateUniqueTempDir()) {
    CHECK(false) << "Failed to create unique temporary directory";
    return;
  }
  base::FilePath stdout_filepath;
  stdout_fd_ = base::CreateAndOpenFdForTemporaryFileInDir(temp_dir_.GetPath(),
                                                          &stdout_filepath);
  base::FilePath stderr_filepath;
  stderr_fd_ = base::CreateAndOpenFdForTemporaryFileInDir(temp_dir_.GetPath(),
                                                          &stderr_filepath);
  return_code_ = -1;
  is_connected_ = false;
}

void FakeProcessControl::GetStdout(GetStdoutCallback callback) {
  std::move(callback).Run(mojo::WrapPlatformFile(
      base::ScopedPlatformFile(HANDLE_EINTR(dup(stdout_fd_.get())))));
}

void FakeProcessControl::GetStderr(GetStderrCallback callback) {
  std::move(callback).Run(mojo::WrapPlatformFile(
      base::ScopedPlatformFile(HANDLE_EINTR(dup(stderr_fd_.get())))));
}

void FakeProcessControl::GetReturnCode(GetReturnCodeCallback callback) {
  if (return_code_ != -1) {
    std::move(callback).Run(return_code_);
    return;
  }
  get_return_code_callbacks_.push_back(std::move(callback));
}

void FakeProcessControl::SetStdoutFileContent(
    const std::string& stdout_content) {
  base::File stdout_file = base::File(HANDLE_EINTR(dup(stdout_fd_.get())));
  stdout_file.Write(/*offset=*/0, stdout_content.c_str(),
                    stdout_content.size());
  stdout_file.Close();
}

void FakeProcessControl::SetStderrFileContent(
    const std::string& stderr_content) {
  base::File stderr_file = base::File(HANDLE_EINTR(dup(stderr_fd_.get())));
  stderr_file.Write(/*offset=*/0, stderr_content.c_str(),
                    stderr_content.size());
  stderr_file.Close();
}

void FakeProcessControl::SetReturnCode(int return_code) {
  CHECK_NE(return_code, -1);
  return_code_ = return_code;
  std::vector<GetReturnCodeCallback> get_return_code_callbacks;
  get_return_code_callbacks.swap(get_return_code_callbacks_);
  for (size_t i = 0; i < get_return_code_callbacks.size(); ++i) {
    std::move(get_return_code_callbacks[i]).Run(return_code);
  }
}

void FakeProcessControl::Kill() {
  if (return_code_ == -1) {
    // The return code if the program is killed by SIGTERM.
    SetReturnCode(143);
  }
}

void FakeProcessControl::BindReceiver(
    mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl> receiver) {
  receiver_.Bind(std::move(receiver));
  is_connected_ = true;
  receiver_.set_disconnect_handler(base::BindOnce(
      [](bool* is_connected) { *is_connected = false; }, &is_connected_));
}

bool FakeProcessControl::IsConnected() {
  return is_connected_;
}

mojo::Receiver<ash::cros_healthd::mojom::ProcessControl>&
FakeProcessControl::receiver() {
  return receiver_;
}

}  // namespace diagnostics
