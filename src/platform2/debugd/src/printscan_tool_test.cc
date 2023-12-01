// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/printscan_tool.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <dbus/mock_bus.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Return;

namespace debugd {

namespace {
const char kCupsDebugPath[] = "run/cups/debug/debug-flag";
const char kIppusbDebugPath[] = "run/ippusb/debug/debug-flag";
const char kLorgnetteDebugPath[] = "run/lorgnette/debug/debug-flag";
}  // namespace

class MockUpstartTools : public UpstartTools {
 public:
  MOCK_METHOD(bool,
              IsJobRunning,
              (const std::string& job_name, brillo::ErrorPtr* error),
              (override));
  MOCK_METHOD(bool,
              RestartJob,
              (const std::string& job_name, brillo::ErrorPtr* error),
              (override));
  MOCK_METHOD(bool,
              StartJob,
              (const std::string& job_name, brillo::ErrorPtr* error),
              (override));
  MOCK_METHOD(bool,
              StopJob,
              (const std::string& job_name, brillo::ErrorPtr* error),
              (override));
};

class PrintscanToolTest : public testing::Test {
 protected:
  base::ScopedTempDir temp_dir_;
  std::unique_ptr<PrintscanTool> printscan_tool_;
  scoped_refptr<dbus::MockBus> bus_;
  MockUpstartTools* mock_upstart_tools_;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(base::SetPosixFilePermissions(temp_dir_.GetPath(), 0755));

    // Create directories we expect PrintscanTool to interact with.
    ASSERT_TRUE(
        base::CreateDirectory(temp_dir_.GetPath().Append("run/cups/debug/")));
    ASSERT_TRUE(
        base::CreateDirectory(temp_dir_.GetPath().Append("run/ippusb/debug/")));
    ASSERT_TRUE(base::CreateDirectory(
        temp_dir_.GetPath().Append("run/lorgnette/debug/")));
    // Set a mock bus for testing.
    bus_ = new dbus::MockBus{dbus::Bus::Options{}};
    std::unique_ptr<MockUpstartTools> mock_upstart_tools =
        std::make_unique<MockUpstartTools>();
    ON_CALL(*mock_upstart_tools, IsJobRunning(_, _))
        .WillByDefault(Return(true));
    ON_CALL(*mock_upstart_tools, RestartJob(_, _)).WillByDefault(Return(true));
    ON_CALL(*mock_upstart_tools, StartJob(_, _)).WillByDefault(Return(true));
    ON_CALL(*mock_upstart_tools, StopJob(_, _)).WillByDefault(Return(true));
    mock_upstart_tools_ = mock_upstart_tools.get();
    // Initialize PrintscanTool with a fake root for testing.
    printscan_tool_ = PrintscanTool::CreateForTesting(
        bus_, temp_dir_.GetPath(), std::move(mock_upstart_tools));
  }
};

TEST_F(PrintscanToolTest, SetNoCategories) {
  brillo::ErrorPtr error;
  // Test disabling debugging when it is already off.
  EXPECT_CALL(*mock_upstart_tools_, RestartJob("cupsd", _));
  EXPECT_CALL(*mock_upstart_tools_, StopJob("lorgnette", _));
  EXPECT_TRUE(printscan_tool_->DebugSetCategories(
      &error, PrintscanCategories::PRINTSCAN_NO_CATEGORIES));
  EXPECT_EQ(error, nullptr);
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_FALSE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, SetPrintingCategory) {
  brillo::ErrorPtr error;
  // Test starting printing debugging only.
  EXPECT_CALL(*mock_upstart_tools_, RestartJob("cupsd", _));
  EXPECT_CALL(*mock_upstart_tools_, StopJob("lorgnette", _));
  EXPECT_TRUE(printscan_tool_->DebugSetCategories(
      &error, PrintscanCategories::PRINTSCAN_PRINTING_CATEGORY));
  EXPECT_EQ(error, nullptr);
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_FALSE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, SetScanningCategory) {
  brillo::ErrorPtr error;
  // Test starting scanning debugging only.
  EXPECT_CALL(*mock_upstart_tools_, RestartJob("cupsd", _));
  EXPECT_CALL(*mock_upstart_tools_, StopJob("lorgnette", _));
  EXPECT_TRUE(printscan_tool_->DebugSetCategories(
      &error, PrintscanCategories::PRINTSCAN_SCANNING_CATEGORY));
  EXPECT_EQ(error, nullptr);
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_TRUE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, SetAllCategories) {
  brillo::ErrorPtr error;
  // Test starting all debugging.
  EXPECT_CALL(*mock_upstart_tools_, RestartJob("cupsd", _));
  EXPECT_CALL(*mock_upstart_tools_, StopJob("lorgnette", _));
  EXPECT_TRUE(printscan_tool_->DebugSetCategories(
      &error, PrintscanCategories::PRINTSCAN_ALL_CATEGORIES));
  EXPECT_EQ(error, nullptr);
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_TRUE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, ResetCategories) {
  brillo::ErrorPtr error;
  // Test starting all debugging.
  EXPECT_CALL(*mock_upstart_tools_, RestartJob("cupsd", _)).Times(2);
  EXPECT_CALL(*mock_upstart_tools_, StopJob("lorgnette", _)).Times(2);
  EXPECT_TRUE(printscan_tool_->DebugSetCategories(
      &error, PrintscanCategories::PRINTSCAN_ALL_CATEGORIES));
  EXPECT_EQ(error, nullptr);
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_TRUE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
  // Test stopping all debugging.
  EXPECT_TRUE(printscan_tool_->DebugSetCategories(
      &error, PrintscanCategories::PRINTSCAN_NO_CATEGORIES));
  EXPECT_EQ(error, nullptr);
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_FALSE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

}  // namespace debugd
