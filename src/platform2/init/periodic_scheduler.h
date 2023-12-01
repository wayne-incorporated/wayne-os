// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_PERIODIC_SCHEDULER_H_
#define INIT_PERIODIC_SCHEDULER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>

// PeriodicScheduler is responsible for executing task `task_name` by running
// `task_exec` every `period` seconds.
class PeriodicScheduler {
 public:
  PeriodicScheduler(const base::TimeDelta& period,
                    const base::TimeDelta& timeout,
                    const std::string& task_name,
                    const std::vector<std::string>& task_exec);
  ~PeriodicScheduler() = default;
  bool Run(bool start_immediately = false);

  void set_spool_dir_for_test(const base::FilePath& spool_dir) {
    spool_dir_ = spool_dir;
  }

  void set_check_freq_for_test(const base::TimeDelta& check_freq) {
    check_frequency_ = check_freq;
  }

 private:
  base::TimeDelta period_seconds_;
  base::TimeDelta timeout_seconds_;
  base::TimeDelta check_frequency_;
  std::string task_name_;
  base::FilePath spool_dir_;
  std::vector<std::string> process_args_;
};

#endif  // INIT_PERIODIC_SCHEDULER_H_
