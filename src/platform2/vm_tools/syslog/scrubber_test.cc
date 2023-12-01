// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <time.h>

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>
#include <vm_protos/proto_bindings/vm_host.pb.h>

#include "vm_tools/syslog/scrubber.h"

using std::string;

namespace vm_tools {
namespace syslog {
namespace {

// NOLINT(whitespace/braces)
constexpr struct SeverityTestCase {
  vm_tools::LogSeverity severity;
  const char* result;
} kSeverityTests[] = {
    {
        .severity = vm_tools::EMERGENCY,
        .result = "<8>",
    },
    {
        .severity = vm_tools::ALERT,
        .result = "<9>",
    },
    {
        .severity = vm_tools::CRITICAL,
        .result = "<10>",
    },
    {
        .severity = vm_tools::ERROR,
        .result = "<11>",
    },
    {
        .severity = vm_tools::WARNING,
        .result = "<12>",
    },
    {
        .severity = vm_tools::NOTICE,
        .result = "<13>",
    },
    {
        .severity = vm_tools::INFO,
        .result = "<14>",
    },
    {
        .severity = vm_tools::DEBUG,
        .result = "<15>",
    },
    {
        .severity = vm_tools::MISSING,
        .result = "<13>",
    },
    {
        .severity = static_cast<vm_tools::LogSeverity>(18),
        .result = "<13>",
    },
};

class SeverityTest : public ::testing::TestWithParam<SeverityTestCase> {};

// NOLINT(whitespace/braces)
constexpr struct TimestampTestCase {
  struct tm tm;
  const char* result;
} kTimestampTests[] = {
    {
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
        .result = "Jan 17 23:54:11",
    },
    {
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
        .result = "Dec 24 18:33:58",
    },
    {
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
        .result = "Jan  1 00:00:00",
    },
    {
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
        .result = "Jun  2 17:15:47",
    },
    {
        // clang-format off
        .tm = {
            .tm_sec = 47,
            .tm_min = 15,
            .tm_hour = 17,
            .tm_mday = 2,
            .tm_mon = 5,
            .tm_year = 57,
        },
        // clang-format on
        .result = "Jun  2 17:15:47",
    },
};

class TimestampTest : public ::testing::TestWithParam<TimestampTestCase> {};

// NOLINT(whitespace/braces)
constexpr struct ContentTestCase {
  const char* input;
  const char* output;
} kContentTests[] = {
    {
        .input = "",
        .output = "",
    },
    {
        .input = "Contains only ASCII characters",
        .output = "Contains only ASCII characters",
    },
    {
        .input = "网页 图片 资讯更多 »",
        .output = "网页 图片 资讯更多 »",
    },
    {
        .input = "Παγκόσμιος Ιστός",
        .output = "Παγκόσμιος Ιστός",
    },
    {
        .input = "Поиск страниц на русском",
        .output = "Поиск страниц на русском",
    },
    {
        // "Embedded (U+008c) control (U+0007) characters"
        .input = "Embedded \xC2\x8C control \x07 characters",

        .output = "Embedded #214 control #007 characters",
    },
    {
        // "Invalid(U+dead) code(U+12ffff) points"
        .input = "Invalid\xED\xBA\xAD code\xF4\xAF\xBF\xBF points",

        // "Invalid��� code��� points"  NOLINT(readability/utf8)
        .output = "Invalid\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD "
                  "code\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD points",
    },
    {
        // "Non-(U+fffe) character (U+fde1) code points"
        .input = "Non-\xEF\xBF\xBE character \xEF\xB7\xA1 code points",

        .output = "Non-#177776 character #176741 code points",
    },
    {
        // "Mix of(U+0091) val(U+001c)id, invalid(U+daaa), 전체Παγκόσμιος网页на
        // русском, non(U+1dffff)-character, and(U+fffe) control (U+fdea) code
        // points"
        .input = "Mix of\xC2\x91 val\x1Cid, invalid\xED\xAA\xAA, "
                 "전체Παγκόσμιος网页на русском, non\xF7\x9F\xBF\xBF-character, "
                 "and\xEF\xBF\xBE control \xEF\xB7\xAA code points",
        .output =
            "Mix of#221 val#034id, "
            "invalid\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD, "
            "전체Παγκόσμιος网页на русском, "
            "non\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD-character, "
            "and#177776 control #176752 code points",
    },
};

class ContentTest : public ::testing::TestWithParam<ContentTestCase> {};

}  // namespace

TEST_P(SeverityTest, ParsesCorrectly) {
  struct SeverityTestCase param = GetParam();

  EXPECT_EQ(ParseProtoSeverity(param.severity), string(param.result));
}
INSTANTIATE_TEST_SUITE_P(Scrubber,
                         SeverityTest,
                         ::testing::ValuesIn(kSeverityTests));

TEST_P(TimestampTest, ParsesCorrectly) {
  struct TimestampTestCase param = GetParam();

  vm_tools::Timestamp timestamp;
  timestamp.set_seconds(mktime(&param.tm));
  ASSERT_NE(timestamp.seconds(), -1);
  EXPECT_EQ(ParseProtoTimestamp(timestamp), string(param.result));
}
INSTANTIATE_TEST_SUITE_P(Scrubber,
                         TimestampTest,
                         ::testing::ValuesIn(kTimestampTests));

TEST_P(ContentTest, ScrubsCleanly) {
  struct ContentTestCase param = GetParam();

  EXPECT_EQ(ScrubProtoContent(param.input), std::string(param.output));
}
INSTANTIATE_TEST_SUITE_P(Scrubber,
                         ContentTest,
                         ::testing::ValuesIn(kContentTests));

TEST(Content, StressTest) {
  base::FilePath src(getenv("PWD"));
  ASSERT_TRUE(base::PathExists(src));

  base::FilePath stress_test = src.Append("syslog").Append("UTF8_test.txt");
  ASSERT_TRUE(base::PathExists(stress_test));

  string content;
  ASSERT_TRUE(base::ReadFileToString(stress_test, &content));
  EXPECT_FALSE(base::IsStringUTF8(content));

  string result = ScrubProtoContent(content);
  EXPECT_TRUE(base::IsStringUTF8(result));
}

}  // namespace syslog
}  // namespace vm_tools
