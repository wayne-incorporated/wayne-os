// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/key_generator.h"

#include <sys/types.h>
#include <unistd.h>

#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <brillo/cryptohome.h>

#include "login_manager/generator_job.h"
#include "login_manager/system_utils.h"

namespace login_manager {

using base::FilePath;
using std::string;
using std::vector;

// static
const char KeyGenerator::kTemporaryKeyFilename[] = "key.pub";

KeyGenerator::Delegate::~Delegate() {}

KeyGenerator::KeyGenerator(uid_t uid, SystemUtils* utils)
    : uid_(uid),
      utils_(utils),
      factory_(std::make_unique<GeneratorJob::Factory>()) {}

KeyGenerator::~KeyGenerator() {}

bool KeyGenerator::Start(const string& username,
                         const base::Optional<base::FilePath>& ns_path) {
  DCHECK(!generating_) << "Must call Reset() between calls to Start()!";
  base::FilePath user_path(brillo::cryptohome::home::GetUserPath(username));
  base::FilePath temporary_key_path(
      user_path.AppendASCII(kTemporaryKeyFilename));
  if (!base::DeleteFile(temporary_key_path)) {
    PLOG(ERROR) << "Old keygen state still present; can't generate keys: ";
    return false;
  }
  key_owner_username_ = username;
  temporary_key_filename_ = temporary_key_path.value();
  keygen_job_ = factory_->Create(temporary_key_filename_, user_path, ns_path,
                                 uid_, utils_);
  if (!keygen_job_->RunInBackground())
    return false;
  pid_t pid = keygen_job_->CurrentPid();
  if (pid < 0)
    return false;
  DLOG(INFO) << "Generating key at " << temporary_key_filename_
             << " using nssdb under " << user_path.value();

  generating_ = true;
  return true;
}

void KeyGenerator::RequestJobExit(const std::string& reason) {
  if (keygen_job_ && keygen_job_->CurrentPid() > 0)
    keygen_job_->Kill(SIGTERM, "");
}

void KeyGenerator::EnsureJobExit(base::TimeDelta timeout) {
  if (keygen_job_ && keygen_job_->CurrentPid() > 0)
    keygen_job_->WaitAndAbort(timeout);
}

bool KeyGenerator::HandleExit(const siginfo_t& info) {
  CHECK(delegate_) << "Must set a delegate before exit can be handled.";
  if (!keygen_job_ || keygen_job_->CurrentPid() <= 0 ||
      keygen_job_->CurrentPid() != info.si_pid) {
    return false;
  }

  if (info.si_status == 0) {
    base::FilePath key_file(temporary_key_filename_);
    delegate_->OnKeyGenerated(key_owner_username_, key_file);
  } else {
    DLOG(WARNING) << "Key generation failed with " << info.si_status;
  }
  Reset();
  return true;
}

void KeyGenerator::InjectJobFactory(
    std::unique_ptr<GeneratorJobFactoryInterface> factory) {
  factory_ = std::move(factory);
}

void KeyGenerator::Reset() {
  key_owner_username_.clear();
  temporary_key_filename_.clear();
  generating_ = false;
}

}  // namespace login_manager
