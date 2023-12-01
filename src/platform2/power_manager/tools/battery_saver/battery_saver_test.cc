// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/tools/battery_saver/battery_saver.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <absl/strings/match.h>
#include <base/command_line.h>
#include <brillo/flag_helper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/dbus-proxy-mocks.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>

#include "power_manager/tools/battery_saver/proto_util.h"

namespace power_manager {
namespace {

using ::testing::_;
using ::testing::ContainsRegex;

MATCHER_P(IsErrorContainingString, s, "is an error containing a string") {
  return !arg.ok() &&
         absl::StrContains(/*haystack=*/arg.status().message(), /*needle=*/s);
}

// Call `ParseCommandLine` with a (more convenient) `std::vector<std::string>`
// argument for the command line args, and resetting static state between
// calls.
absl::StatusOr<BsmCommand> ParseCommandLine(std::vector<std::string> args) {
  // Create an array of const char* args, and feed it to `ParseCommandLine`.
  std::vector<const char*> c_args;
  c_args.push_back("battery_saver");  // program name
  for (const std::string& arg : args) {
    c_args.push_back(arg.c_str());
  }

  // Resetting libbrillo and libbase's internal caches.
  base::CommandLine::Reset();
  brillo::FlagHelper::ResetForTesting();

  // Call the ParseCommandLine command.
  return power_manager::ParseCommandLine(c_args.size(), c_args.data());
}

TEST(ParseCommandLine, NoArgs) {
  EXPECT_THAT(ParseCommandLine({}),
              IsErrorContainingString("Expected exactly one command"));
}

TEST(ParseCommandLine, ValidCommands) {
  EXPECT_EQ(ParseCommandLine({"enable"}),
            absl::StatusOr<BsmCommand>(BsmCommand::kEnable));
  EXPECT_EQ(ParseCommandLine({"disable"}),
            absl::StatusOr<BsmCommand>{BsmCommand::kDisable});
  EXPECT_EQ(ParseCommandLine({"status"}),
            absl::StatusOr<BsmCommand>{BsmCommand::kStatus});
}

TEST(ParseCommandLine, ExtraneousArgs) {
  EXPECT_THAT(ParseCommandLine({"enable", "--invalid"}),
              IsErrorContainingString("Invalid option specified"));
  EXPECT_THAT(ParseCommandLine({"enable", "disable"}),
              IsErrorContainingString("Expected exactly one command"));
}

TEST(SetBsmEnabled, Enable) {
  org::chromium::PowerManagerProxyMock power_manager;

  // Expect a call to `SetBatterySaverModeState`, and save the result.
  std::optional<std::vector<uint8_t>> parameter;
  EXPECT_CALL(power_manager, SetBatterySaverModeState(_, _, _))
      .WillOnce([&](std::vector<uint8_t> vector, brillo::ErrorPtr* error,
                    int timeout) -> bool {
        parameter = std::move(vector);
        return true;
      });

  ASSERT_TRUE(SetBsmEnabled(power_manager, /*enable=*/true).ok());

  // Ensure the proto arg is valid.
  ASSERT_TRUE(parameter.has_value());
  std::optional<BatterySaverModeState> deserialized =
      DeserializeProto<BatterySaverModeState>(*parameter);
  ASSERT_TRUE(deserialized.has_value());
  EXPECT_TRUE(deserialized->enabled());
}

TEST(SetBsmEnabled, Error) {
  org::chromium::PowerManagerProxyMock power_manager;

  // `SetBatterySaverModeState` returns an error.
  std::optional<std::vector<uint8_t>> parameter;
  EXPECT_CALL(power_manager, SetBatterySaverModeState(_, _, _))
      .WillOnce([&](std::vector<uint8_t> vector, brillo::ErrorPtr* error,
                    int timeout) -> bool {
        *error = brillo::Error::CreateNoLog(FROM_HERE, "test_error",
                                            "test_code", "dbus error", nullptr);
        return false;
      });

  // Make the call, and ensure a valid error was returned.
  absl::Status status = SetBsmEnabled(power_manager, /*enable=*/true);
  ASSERT_FALSE(status.ok());
  EXPECT_THAT(std::string(status.message()),
              testing::ContainsRegex(
                  "Failed to update battery saver mode state: dbus error"));
}

TEST(GetBsmState, Simple) {
  org::chromium::PowerManagerProxyMock power_manager;

  EXPECT_CALL(power_manager, GetBatterySaverModeState(_, _, _))
      .WillOnce([&](std::vector<uint8_t>* vector, brillo::ErrorPtr* error,
                    int timeout) -> bool {
        BatterySaverModeState state;
        state.set_enabled(true);
        *vector = SerializeProto(state);
        return true;
      });

  absl::StatusOr<BatterySaverModeState> result = GetBsmState(power_manager);
  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result->enabled());
}

TEST(GetBsmState, Error) {
  org::chromium::PowerManagerProxyMock power_manager;

  EXPECT_CALL(power_manager, GetBatterySaverModeState(_, _, _))
      .WillOnce([&](std::vector<uint8_t>* vector, brillo::ErrorPtr* error,
                    int timeout) -> bool {
        *error = brillo::Error::CreateNoLog(FROM_HERE, "test_error",
                                            "test_code", "dbus error", nullptr);
        return false;
      });

  absl::StatusOr<BatterySaverModeState> result = GetBsmState(power_manager);
  ASSERT_FALSE(result.ok());
  EXPECT_THAT(
      std::string(result.status().message()),
      testing::ContainsRegex(
          "Failed to fetch current battery saver mode state: dbus error"));
}

TEST(BatterySaverModeStateToString, Basic) {
  // Default BatterySaverModeState instance.
  EXPECT_EQ(BatterySaverModeStateToString(BatterySaverModeState{}),
            "{ enabled: false; cause: CAUSE_UNSPECIFIED }");

  // BatterySaverModeState instance with all fields set.
  {
    BatterySaverModeState state;
    state.set_enabled(true);
    state.set_cause(BatterySaverModeState::CAUSE_USER_ENABLED);
    EXPECT_EQ(BatterySaverModeStateToString(state),
              "{ enabled: true; cause: CAUSE_USER_ENABLED }");
  }
}

}  // namespace
}  // namespace power_manager
