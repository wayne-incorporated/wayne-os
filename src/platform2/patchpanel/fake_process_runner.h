// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_FAKE_PROCESS_RUNNER_H_
#define PATCHPANEL_FAKE_PROCESS_RUNNER_H_

#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_util.h>

#include <gtest/gtest.h>

#include "patchpanel/minijailed_process_runner.h"

namespace patchpanel {

class FakeProcessRunner : public MinijailedProcessRunner {
 public:
  explicit FakeProcessRunner(std::vector<std::string>* runs = nullptr)
      : runs_(runs ? runs : &runs_vec_) {}
  FakeProcessRunner(const FakeProcessRunner&) = delete;
  FakeProcessRunner& operator=(const FakeProcessRunner&) = delete;

  ~FakeProcessRunner() = default;

  int Run(const std::vector<std::string>& argv, bool log_failures) override {
    if (capture_)
      runs_->emplace_back(base::JoinString(argv, " "));
    if (run_override_)
      return run_override_.Run(argv);
    return 0;
  }

  void Capture(bool on, std::vector<std::string>* runs = nullptr) {
    capture_ = on;
    if (runs)
      runs_ = runs;
  }

  void VerifyRuns(const std::vector<std::string>& expected) {
    VerifyRuns(*runs_, expected);
  }

  static void VerifyRuns(const std::vector<std::string>& got,
                         const std::vector<std::string>& expected) {
    ASSERT_EQ(got.size(), expected.size());
    for (int i = 0; i < got.size(); ++i) {
      EXPECT_EQ(got[i], expected[i]);
    }
  }

  void VerifyAddInterface(const std::string& host_ifname,
                          const std::string& con_ifname,
                          uint32_t con_ipv4,
                          uint32_t con_prefix_len,
                          bool enable_multicast,
                          const std::string& con_pid) {
    EXPECT_EQ(host_ifname, add_host_ifname_);
    EXPECT_EQ(con_ifname, add_con_ifname_);
    EXPECT_EQ(con_ipv4, add_con_ipv4_);
    EXPECT_EQ(con_prefix_len, add_con_prefix_len_);
    EXPECT_EQ(enable_multicast, add_enable_multicast_);
    EXPECT_EQ(con_pid, add_con_pid_);
  }

  void SetRunOverride(
      base::RepeatingCallback<int(const std::vector<std::string>&)> callback) {
    run_override_ = std::move(callback);
  }

 private:
  bool capture_ = false;
  base::RepeatingCallback<int(const std::vector<std::string>&)> run_override_;
  std::vector<std::string>* runs_;
  std::vector<std::string> runs_vec_;
  std::string add_host_ifname_;
  std::string add_con_ifname_;
  uint32_t add_con_ipv4_;
  uint32_t add_con_prefix_len_;
  bool add_enable_multicast_;
  std::string add_con_pid_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_FAKE_PROCESS_RUNNER_H_
