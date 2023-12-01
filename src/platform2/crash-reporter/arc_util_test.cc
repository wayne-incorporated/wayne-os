// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/arc_util.h"

#include <algorithm>
#include <memory>

#include <base/test/simple_test_tick_clock.h>
#include <brillo/syslog_logging.h>
#include <gtest/gtest.h>
#include <session_manager/dbus-proxy-mocks.h>

using brillo::ClearLog;
using brillo::FindLog;
using brillo::GetLog;

namespace arc_util {

namespace {

constexpr char kUnknownValue[] = "unknown";

const char kCrashLog[] = R"(Process: com.arc.app
Flags: 0xcafebabe
Package: com.arc.app v1 (1.0)
Build: fingerprint

Line 1
Line 2
Line 3
)";

}  // namespace

TEST(ArcUtilTest, ParseCrashLog) {
  CrashLogHeaderMap map;
  std::string exception_info, log;

  // Crash log should not be empty.
  EXPECT_FALSE(
      ParseCrashLog("system_app_crash", "", &map, &exception_info, &log));

  // Header key should be followed by a colon.
  EXPECT_FALSE(
      ParseCrashLog("system_app_crash", "Key", &map, &exception_info, &log));

  EXPECT_TRUE(FindLog("Header has unexpected format"));
  ClearLog();

  // Header value should not be empty.
  EXPECT_FALSE(ParseCrashLog("system_app_crash", "Key:   ", &map,
                             &exception_info, &log));

  EXPECT_TRUE(FindLog("Header has unexpected format"));
  ClearLog();

  // Parse a crash log with exception info.
  EXPECT_TRUE(ParseCrashLog("system_app_crash", kCrashLog, &map,
                            &exception_info, &log));

  EXPECT_TRUE(GetLog().empty());

  EXPECT_EQ("com.arc.app", GetCrashLogHeader(map, "Process"));
  EXPECT_EQ("fingerprint", GetCrashLogHeader(map, "Build"));
  EXPECT_EQ("unknown", GetCrashLogHeader(map, "Activity"));
  EXPECT_EQ("Line 1\nLine 2\nLine 3\n", exception_info);

  // Parse a crash log without exception info.
  map.clear();
  exception_info.clear();
  EXPECT_TRUE(
      ParseCrashLog("system_app_anr", kCrashLog, &map, &exception_info, &log));

  EXPECT_TRUE(GetLog().empty());

  EXPECT_EQ("0xcafebabe", GetCrashLogHeader(map, "Flags"));
  EXPECT_EQ("com.arc.app v1 (1.0)", GetCrashLogHeader(map, "Package"));
  EXPECT_TRUE(exception_info.empty());
}

TEST(ArcUtilTest, GetAndroidVersion) {
  const std::pair<const char*, const char*> tests[] = {
      // version / fingerprint
      {"7.1.1",
       "google/caroline/caroline_cheets:7.1.1/R65-10317.0.9999/"
       "4548207:user/release-keys"},
      {"7.1.1",
       "google/banon/banon_cheets:7.1.1/R62-9901.77.0/"
       "4446936:user/release-keys"},
      {"6.0.1",
       "google/cyan/cyan_cheets:6.0.1/R60-9592.85.0/"
       "4284198:user/release-keys"},
      {"6.0.1",
       "google/minnie/minnie_cheets:6.0.1/R60-9592.96.0/"
       "4328948:user/release-keys"},
      {"7.1.1",
       "google/cyan/cyan_cheets:7.1.1/R61-9765.85.0/"
       "4391409:user/release-keys"},
      {"7.1.1",
       "google/banon/banon_cheets:7.1.1/R62-9901.66.0/"
       "4421464:user/release-keys"},
      {"7.1.1",
       "google/edgar/edgar_cheets:7.1.1/R62-9901.77.0/"
       "4446936:user/release-keys"},
      {"7.1.1",
       "google/celes/celes_cheets:7.1.1/R63-10032.75.0/"
       "4505339:user/release-keys"},
      {"7.1.1",
       "google/edgar/edgar_cheets:7.1.1/R64-10134.0.0/"
       "4453597:user/release-keys"},
      {"7.1.1",
       "google/fizz/fizz_cheets:7.1.1/R64-10176.13.1/"
       "4496886:user/release-keys"},
      {"7.1.1",
       "google/kevin/kevin_cheets:7.1.1/R64-10176.22.0/"
       "4510202:user/release-keys"},
      {"7.1.1",
       "google/celes/celes_cheets:7.1.1/R65-10278.0.0/"
       "4524556:user/release-keys"},

      // fake ones
      {"70.10.10.10",
       "google/celes/celes_cheets:70.10.10.10/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"7.1.1.1",
       "google/celes/celes_cheets:7.1.1.1/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"7.1.1",
       "google/celes/celes_cheets:7.1.1/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"7.1",
       "google/celes/celes_cheets:7.1/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"7",
       "google/celes/celes_cheets:7/R65-10278.0.0/"
       "4524556:user/release-keys"},

      // future-proofing tests
      {"test.1",
       "google/celes/celes_cheets:test.1/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"7.1.1a",
       "google/celes/celes_cheets:7.1.1a/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"7a",
       "google/celes/celes_cheets:7a/R65-10278.0.0/"
       "4524556:user/release-keys"},
      {"9", ":9/R"},

      // failed ones
      {kUnknownValue,
       "google/celes/celes_cheets:1.1/"
       "65-10278.0.0/4524556:user/release-keys"},
      {kUnknownValue,
       "google/celes/celes_cheets:1.1/"
       "65-10278.0.0/4524556:user/7.1.1"},
      {kUnknownValue,
       "google/celes/celes_cheets:/"
       "R65-10278.0.0/4524556:user/7.1.1"},
      {kUnknownValue,
       "google/celes/celes_cheets:/"
       "65-10278.0.0/4524556:user/7.1.1"},
      {kUnknownValue, ":/"},
      {kUnknownValue, ":/R"},
      {kUnknownValue, "/R:"},
      {kUnknownValue, ""},
      {kUnknownValue, ":"},
      {kUnknownValue, "/R"},
  };

  for (const auto& item : tests) {
    EXPECT_EQ(item.first,
              GetVersionFromFingerprint(item.second).value_or(kUnknownValue));
  }
}

TEST(ArcUtilTest, ListMetadataForBuildProperty) {
  constexpr char kDevice[] = "rammus_cheets";
  constexpr char kBoard[] = "shyvana";
  constexpr char kCpuAbi[] = "x86_64";
  constexpr char kFingerprint[] =
      "google/rammus/rammus_cheets:11/R87-13443.0.0/6801612:user/release-keys";
  constexpr char kAndroidVersionInFingerprint[] = "11";
  const BuildProperty build_property = {.device = kDevice,
                                        .board = kBoard,
                                        .cpu_abi = kCpuAbi,
                                        .fingerprint = kFingerprint};

  std::vector<std::pair<std::string, std::string>> expected_metadata{
      // key / value
      {kArcVersionField, kFingerprint},
      {kAndroidVersionField, kAndroidVersionInFingerprint},
      {kDeviceField, kDevice},
      {kBoardField, kBoard},
      {kCpuAbiField, kCpuAbi},
  };

  std::vector<std::pair<std::string, std::string>> metadata =
      ListMetadataForBuildProperty(build_property);

  std::sort(expected_metadata.begin(), expected_metadata.end());
  std::sort(metadata.begin(), metadata.end());
  EXPECT_EQ(metadata, expected_metadata);
}

TEST(ArcUtilTest, FormatDuration) {
  EXPECT_EQ(FormatDuration(base::TimeDelta()), "0s");
  EXPECT_EQ(FormatDuration(base::Milliseconds(999)), "0s");
  EXPECT_EQ(FormatDuration(base::Seconds(1)), "1s");
  EXPECT_EQ(FormatDuration(base::Minutes(2)), "2min 0s");
  EXPECT_EQ(FormatDuration(base::Hours(3)), "3h 0min 0s");
  EXPECT_EQ(FormatDuration(base::Days(4)), "4d 0h 0min 0s");
  EXPECT_EQ(
      FormatDuration(base::Hours(1) + base::Minutes(2) + base::Seconds(3)),
      "1h 2min 3s");
  EXPECT_EQ(FormatDuration(base::Milliseconds(123456789)), "1d 10h 17min 36s");
  EXPECT_EQ(FormatDuration(base::Days(365)), "365d 0h 0min 0s");
}

TEST(ArcUtilTest, GetArcContainerUptime) {
  base::TimeDelta expected = base::Milliseconds(1234567);
  int64_t start_time = 1234567890;
  base::SimpleTestTickClock test_clock;
  test_clock.SetNowTicks(base::TimeTicks::FromInternalValue(start_time) +
                         expected);

  auto mock =
      std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
  EXPECT_CALL(*mock, GetArcStartTimeTicks)
      .WillOnce(
          testing::Invoke([start_time](int64_t* start_time_ptr,
                                       brillo::ErrorPtr* error, int value) {
            *start_time_ptr = start_time;
            return true;
          }));

  base::TimeDelta actual;
  EXPECT_TRUE(GetArcContainerUptime(mock.get(), &actual, &test_clock));
  EXPECT_EQ(actual, expected);
}

}  // namespace arc_util
