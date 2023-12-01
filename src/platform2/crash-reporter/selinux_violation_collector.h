// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The SELinux violation collector gathers information about SELinux audit
// events. Anomaly detector invokes it when it sees a matching line in the
// journal.

#ifndef CRASH_REPORTER_SELINUX_VIOLATION_COLLECTOR_H_
#define CRASH_REPORTER_SELINUX_VIOLATION_COLLECTOR_H_

#include <map>
#include <string>

#include <base/files/file_util.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"

// SELinux violation collector.
class SELinuxViolationCollector : public CrashCollector {
 public:
  SELinuxViolationCollector();
  SELinuxViolationCollector(const SELinuxViolationCollector&) = delete;
  SELinuxViolationCollector& operator=(const SELinuxViolationCollector&) =
      delete;

  ~SELinuxViolationCollector() override;

  // Collects warning.
  bool Collect(int32_t weight);

  static CollectorInfo GetHandlerInfo(bool selinux_violation, int32_t weight);

 protected:
  void set_violation_report_path_for_testing(const base::FilePath& file_path) {
    violation_report_path_ = file_path;
  }

 private:
  friend class SELinuxViolationCollectorTest;
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectOK);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectOKWithComm);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectOKWithPid);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectOKWithPidAndComm);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectWithInvalidComm);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectWithLongComm);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectWithNonTerminatedComm);
  FRIEND_TEST(SELinuxViolationCollectorTest, CollectSample);

  base::FilePath violation_report_path_;
  int fake_random_for_statistic_sampling_ = -1;

  bool LoadSELinuxViolation(std::string* content,
                            std::string* signature,
                            std::map<std::string, std::string>* extra_metadata);

  bool ShouldDropThisReport();
};

#endif  // CRASH_REPORTER_SELINUX_VIOLATION_COLLECTOR_H_
