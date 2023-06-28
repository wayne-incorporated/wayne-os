// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_generator_job.h"

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/time/time.h>

#include "login_manager/generator_job.h"
#include "login_manager/key_generator.h"

namespace login_manager {

FakeGeneratorJob::Factory::Factory(pid_t pid,
                                   const std::string& name,
                                   const std::string& key_contents)
    : pid_(pid), name_(name), key_contents_(key_contents) {}
FakeGeneratorJob::Factory::~Factory() {}

std::unique_ptr<GeneratorJobInterface> FakeGeneratorJob::Factory::Create(
    const std::string& filename,
    const base::FilePath& user_path,
    const base::Optional<base::FilePath> ns_path,
    uid_t desired_uid,
    SystemUtils* utils) {
  return std::unique_ptr<GeneratorJobInterface>(
      new FakeGeneratorJob(pid_, name_, key_contents_, filename));
}

FakeGeneratorJob::FakeGeneratorJob(pid_t pid,
                                   const std::string& name,
                                   const std::string& key_contents,
                                   const std::string& filename)
    : pid_(pid),
      name_(name),
      key_contents_(key_contents),
      filename_(filename) {}
FakeGeneratorJob::~FakeGeneratorJob() {}

bool FakeGeneratorJob::RunInBackground() {
  base::FilePath full_path(filename_);
  if (!base::CreateDirectory(full_path.DirName())) {
    PLOG(ERROR) << "Could not create directory " << full_path.DirName().value();
    return false;
  }
  size_t bytes_written =
      base::WriteFile(full_path, key_contents_.c_str(), key_contents_.size());
  if (bytes_written == key_contents_.size())
    return true;
  PLOG(ERROR) << "Could not write " << filename_;
  return false;
}

}  // namespace login_manager
