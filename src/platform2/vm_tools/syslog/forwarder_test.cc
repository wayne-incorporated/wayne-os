// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/socket.h>
#include <time.h>

#include <memory>
#include <string>

#include <base/files/scoped_file.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <vm_protos/proto_bindings/vm_host.pb.h>

#include "vm_tools/syslog/forwarder.h"

using std::string;

namespace vm_tools {
namespace syslog {
namespace {

constexpr struct {
  vm_tools::LogSeverity severity;
  struct tm tm;
  const char* content;
  const char* result;
} kEndToEndTests[] = {
    {
        .severity = vm_tools::ERROR,
        // clang-format off
        .tm = {
            .tm_sec = 11,
            .tm_min = 54,
            .tm_hour = 23,
            .tm_mday = 17,
            .tm_mon = 0,
            .tm_year = 125,
        },
        // clang-format on
        .content = "网页 图片 资讯更多 »",
        .result = "<11>Jan 17 23:54:11 VM(0): 网页 图片 资讯更多 »",
    },
    {
        .severity = vm_tools::EMERGENCY,
        // clang-format off
        .tm = {
            .tm_sec = 58,
            .tm_min = 33,
            .tm_hour = 18,
            .tm_mday = 24,
            .tm_mon = 11,
            .tm_year = 6,
        },
        // clang-format on
        .content = "Invalid\xED\xBA\xAD code\xF4\xAF\xBF\xBF points",
        .result = "<8>Dec 24 18:33:58 VM(0): "
                  "Invalid\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD "
                  "code\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD points",
    },
    {
        .severity = vm_tools::DEBUG,
        // clang-format off
        .tm = {
            .tm_sec = 0,
            .tm_min = 0,
            .tm_hour = 0,
            .tm_mday = 1,
            .tm_mon = 0,
            .tm_year = 70,
        },
        // clang-format on
        .content = "Non-\xEF\xBF\xBE character \xEF\xB7\xA1 code points",
        .result = "<15>Jan  1 00:00:00 VM(0): Non-#177776 character "
                  "#176741 code points",
    },
    {
        .severity = vm_tools::NOTICE,
        // clang-format off
        .tm = {
            .tm_sec = 47,
            .tm_min = 15,
            .tm_hour = 17,
            .tm_mday = 2,
            .tm_mon = 5,
            .tm_year = 112,
        },
        // clang-format on
        .content = "Mix of\xC2\x91 val\x1Cid, invalid\xED\xAA\xAA, "
                   "전체Παγκόσμιος网页на русском, "
                   "non\xF7\x9F\xBF\xBF-character, and\xEF\xBF\xBE control "
                   "\xEF\xB7\xAA code points",
        .result = "<13>Jun  2 17:15:47 VM(0): Mix of#221 val#034id, "
                  "invalid\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD, "
                  "전체Παγκόσμιος网页на русском, "
                  "non\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD-"
                  "character, and#177776 control #176752 "
                  "code points",
    },
};

}  //  namespace

TEST(ForwarderTest, EndToEnd) {
  int fds[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds), 0);

  base::ScopedFD receiver(fds[0]);
  auto forwarder = std::make_unique<Forwarder>(base::ScopedFD(fds[1]));

  vm_tools::LogRequest request;
  for (const auto& test_case : kEndToEndTests) {
    vm_tools::LogRecord* record = request.add_records();

    record->set_severity(test_case.severity);

    // Needs to be copied because mktime will modify it.
    struct tm timestamp = test_case.tm;
    record->mutable_timestamp()->set_seconds(mktime(&timestamp));
    ASSERT_NE(record->timestamp().seconds(), -1);

    record->set_content(test_case.content);
  }

  grpc::Status status = forwarder->ForwardLogs(0, request);

  ASSERT_TRUE(status.ok());

  for (const auto& test_case : kEndToEndTests) {
    char buf[1024];
    ssize_t len = strlen(test_case.result);
    ASSERT_LE(len + 1, sizeof(buf));
    EXPECT_EQ(recv(receiver.get(), buf, sizeof(buf), 0), len);

    EXPECT_EQ(std::string(buf, len), std::string(test_case.result));
  }
}

}  // namespace syslog
}  // namespace vm_tools
