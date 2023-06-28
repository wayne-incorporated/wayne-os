// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_FAKE_GENERATOR_JOB_H_
#define LOGIN_MANAGER_FAKE_GENERATOR_JOB_H_

#include "login_manager/generator_job.h"

#include <signal.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/time/time.h>
#include <gmock/gmock.h>

namespace login_manager {
class FakeGeneratorJob : public GeneratorJobInterface {
 public:
  class Factory : public GeneratorJobFactoryInterface {
   public:
    Factory(pid_t pid,
            const std::string& name,
            const std::string& key_contents);
    Factory(const Factory&) = delete;
    Factory& operator=(const Factory&) = delete;

    ~Factory() override;
    std::unique_ptr<GeneratorJobInterface> Create(
        const std::string& filename,
        const base::FilePath& user_path,
        const base::Optional<base::FilePath> ns_path,
        uid_t desired_uid,
        SystemUtils* utils) override;

   private:
    pid_t pid_;
    const std::string name_;
    const std::string key_contents_;
  };

  FakeGeneratorJob(pid_t pid,
                   const std::string& name,
                   const std::string& key_contents,
                   const std::string& filename);
  FakeGeneratorJob(const FakeGeneratorJob&) = delete;
  FakeGeneratorJob& operator=(const FakeGeneratorJob&) = delete;

  ~FakeGeneratorJob() override;

  bool RunInBackground() override;
  MOCK_METHOD(void, KillEverything, (int, const std::string&), (override));
  MOCK_METHOD(void, Kill, (int, const std::string&), (override));
  MOCK_METHOD(void, WaitAndAbort, (base::TimeDelta), (override));

  const std::string GetName() const override { return name_; }
  pid_t CurrentPid() const override { return pid_; }

 private:
  pid_t pid_;
  const std::string name_;
  const std::string key_contents_;
  const std::string filename_;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_FAKE_GENERATOR_JOB_H_
