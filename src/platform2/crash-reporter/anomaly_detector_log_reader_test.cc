// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector_log_reader.h"
#include "crash-reporter/anomaly_detector_text_file_reader.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest.h>
#include <re2/re2.h>

#include "crash-reporter/test_util.h"

namespace anomaly {

using ReaderRun = std::vector<LogEntry>;

// This initialises either AuditReader or MessageReader which is an
// implementation of abstract LogReader class.
template <typename T>
std::unique_ptr<LogReader> InitializeLogReaderForTest(
    const std::string& input_file_name, const char* pattern) {
  base::FilePath input_file_path =
      test_util::GetTestDataPath(input_file_name, /*use_testdata=*/true);
  auto r = std::make_unique<T>(input_file_path, pattern);

  return r;
}

void ReaderTest(const std::unique_ptr<LogReader>& r, const ReaderRun& want) {
  ReaderRun got{};
  LogEntry entry;
  while (r->GetNextEntry(&entry)) {
    got.push_back(entry);
  }
  ASSERT_EQ(want.size(), got.size());

  for (int i = 0; i < want.size(); i++) {
    EXPECT_EQ(want[i].tag, got[i].tag);
    EXPECT_EQ(want[i].message, got[i].message);
    EXPECT_EQ(want[i].timestamp.ToTimeT(), got[i].timestamp.ToTimeT());
  }
}

// Tests if initialisation of LogReader moves the current position of log_file_
// member to the end of the file avoiding re-reading of old logs.
TEST(AnomalyDetectorLogReaderTest, NoRereadingTest) {
  auto ar = InitializeLogReaderForTest<AuditReader>("TEST_AUDIT_LOG",
                                                    kAuditLogPattern);
  ReaderTest(ar, {});
}

TEST(AnomalyDetectorLogReaderTest, AuditReaderTest) {
  auto ar = InitializeLogReaderForTest<AuditReader>("TEST_AUDIT_LOG",
                                                    kAuditLogPattern);
  // Make the LogReader read file from the beginning.
  ar->SeekToBegin();

  LogEntry e1{
      .tag = "audit",
      .message =
          R"(avc:  denied  { module_request } for  )"
          R"(pid=1795 comm="init" kmod="fs-cgroup2" scontext)"
          R"(=u:r:init:s0 tcontext=u:r:kernel:s0 tclass=system permissive=0)",
      .timestamp = base::Time::FromTimeT(1588751099)};
  LogEntry e2 = {
      .tag = "audit",
      .message = R"(avc:  granted  { associate } for  pid=3052 comm="emerge")"
                 R"( name="crash_sender#new" scontext=u:object_r:rootfs:s0)"
                 R"( tcontext=u:object_r:labeledfs:s0 tclass=filesystem)",
      .timestamp = base::Time::FromTimeT(1589342085)};

  ReaderRun want{std::move(e1), std::move(e2)};
  ReaderTest(ar, want);
}

TEST(AnomalyDetectorLogReaderTest, MessageReaderTest) {
  auto mr = InitializeLogReaderForTest<MessageReader>("TEST_MESSAGE_LOG",
                                                      kMessageLogPattern);
  // Make the LogReader read file from the beginning.
  mr->SeekToBegin();

  LogEntry e1{.tag = "tpm_managerd",
              .message =
                  R"(TPM error 0x3011 (Communication failure): Failed to)"
                  R"( connect context.)",
              .timestamp = base::Time::FromTimeT(1589150704)};
  LogEntry e2{
      .tag = "rsyslogd",
      .message =
          R"([origin software="rsyslogd" swVersion="8.1904.0" x-pid="642")"
          R"( x-info="https://www.rsyslog.com"] rsyslogd was HUPed)",
      .timestamp = base::Time::FromTimeT(1589316963)};
  LogEntry e3{.tag = "kernel",
              .message = R"([  893.009245] atme1_mxt_ts 3-004b:)"
                         R"( Status: 00 Config Checksum: 673e89)",
              .timestamp = base::Time::FromTimeT(1589370987)};
  LogEntry e4{.tag = "VM(3)",
              .message =
                  "[devices/src/virtio/balloon.rs:290] ballon "
                  "config changed to consume 255836 pages",
              .timestamp = base::Time::FromTimeT(1589485024)};
  LogEntry e5{.tag = "",
              .message = "log message with no tag.",
              .timestamp = base::Time::FromTimeT(1591604929)};

  ReaderRun want{std::move(e1), std::move(e2), std::move(e3), std::move(e4),
                 std::move(e5)};
  ReaderTest(mr, want);
}

TEST(AnomalyDetectorLogReaderTest, UpstartMessageReaderTest) {
  auto mr = InitializeLogReaderForTest<MessageReader>("TEST_UPSTART_LOG",
                                                      kUpstartLogPattern);
  // Make the LogReader read file from the beginning.
  mr->SeekToBegin();

  LogEntry e1{.tag = "init",
              .message = "Connection from private client",
              .timestamp = base::Time::FromTimeT(1589560440)};
  LogEntry e2{
      .tag = "init",
      .message = "early-failure main process (168) terminated with status 124",
      .timestamp = base::Time::FromTimeT(1589572174)};
  LogEntry e3{.tag = "init",
              .message = "vpd-log main process (440) terminated with status 1",
              .timestamp = base::Time::FromTimeT(1589572176)};

  ReaderRun want{std::move(e1), std::move(e2), std::move(e3)};
  ReaderTest(mr, want);
}

}  // namespace anomaly
