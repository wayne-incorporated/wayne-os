// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/daemon/printscan_tool.h"

#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <printscanmgr/proto_bindings/printscanmgr_service.pb.h>

#include "printscanmgr/executor/mock_executor.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;
using ::testing::WithArg;

namespace printscanmgr {

namespace {

const char kCupsDebugPath[] = "run/cups/debug/debug-flag";
const char kIppusbDebugPath[] = "run/ippusb/debug/debug-flag";
const char kLorgnetteDebugPath[] = "run/lorgnette/debug/debug-flag";

}  // namespace

class PrintscanToolTest : public testing::Test {
 protected:
  base::ScopedTempDir temp_dir_;
  StrictMock<MockExecutor> mock_executor_;
  std::unique_ptr<PrintscanTool> printscan_tool_;

  void SetUp() override {
    // Initialize IPC support for Mojo.
    ipc_support_ = std::make_unique<::mojo::core::ScopedIPCSupport>(
        base::SingleThreadTaskRunner::
            GetCurrentDefault() /* io_thread_task_runner */,
        ::mojo::core::ScopedIPCSupport::ShutdownPolicy::
            CLEAN /* blocking shutdown */);

    // Create directories we expect PrintscanTool to interact with.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    ASSERT_TRUE(base::SetPosixFilePermissions(temp_dir_.GetPath(), 0755));
    ASSERT_TRUE(
        base::CreateDirectory(temp_dir_.GetPath().Append("run/cups/debug/")));
    ASSERT_TRUE(
        base::CreateDirectory(temp_dir_.GetPath().Append("run/ippusb/debug/")));
    ASSERT_TRUE(base::CreateDirectory(
        temp_dir_.GetPath().Append("run/lorgnette/debug/")));

    // Prepare default responses for the mock Mojo methods.
    ON_CALL(mock_executor_, StopUpstartJob(_, _))
        .WillByDefault(WithArg<1>(
            Invoke([](mojom::Executor::StopUpstartJobCallback callback) {
              std::move(callback).Run(/*success=*/true, /*errorMsg=*/"");
            })));
    ON_CALL(mock_executor_, RestartUpstartJob(_, _))
        .WillByDefault(WithArg<1>(
            Invoke([](mojom::Executor::RestartUpstartJobCallback callback) {
              std::move(callback).Run(/*success=*/true, /*errorMsg=*/"");
            })));

    // Initialize PrintscanTool with a fake root for testing.
    printscan_tool_ = PrintscanTool::CreateForTesting(
        mock_executor_.pending_remote(), temp_dir_.GetPath());
  }

 private:
  base::test::SingleThreadTaskEnvironment task_environment_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
};

TEST_F(PrintscanToolTest, SetNoCategories) {
  // Test disabling debugging when it is already off.
  EXPECT_CALL(mock_executor_, RestartUpstartJob(mojom::UpstartJob::kCupsd, _));
  EXPECT_CALL(mock_executor_, StopUpstartJob(mojom::UpstartJob::kLorgnette, _));
  PrintscanDebugSetCategoriesRequest request;

  auto response = printscan_tool_->DebugSetCategories(request);

  EXPECT_TRUE(response.result());
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_FALSE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, SetPrintingCategory) {
  // Test starting printing debugging only.
  EXPECT_CALL(mock_executor_, RestartUpstartJob(mojom::UpstartJob::kCupsd, _));
  EXPECT_CALL(mock_executor_, StopUpstartJob(mojom::UpstartJob::kLorgnette, _));
  PrintscanDebugSetCategoriesRequest request;
  request.add_categories(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_PRINTING);

  auto response = printscan_tool_->DebugSetCategories(request);

  EXPECT_TRUE(response.result());
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_FALSE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, SetScanningCategory) {
  // Test starting scanning debugging only.
  EXPECT_CALL(mock_executor_, RestartUpstartJob(mojom::UpstartJob::kCupsd, _));
  EXPECT_CALL(mock_executor_, StopUpstartJob(mojom::UpstartJob::kLorgnette, _));
  PrintscanDebugSetCategoriesRequest request;
  request.add_categories(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_SCANNING);

  auto response = printscan_tool_->DebugSetCategories(request);

  EXPECT_TRUE(response.result());
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_TRUE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, SetAllCategories) {
  // Test starting all debugging.
  EXPECT_CALL(mock_executor_, RestartUpstartJob(mojom::UpstartJob::kCupsd, _));
  EXPECT_CALL(mock_executor_, StopUpstartJob(mojom::UpstartJob::kLorgnette, _));
  PrintscanDebugSetCategoriesRequest request;
  request.add_categories(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_PRINTING);
  request.add_categories(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_SCANNING);

  auto response = printscan_tool_->DebugSetCategories(request);

  EXPECT_TRUE(response.result());
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_TRUE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

TEST_F(PrintscanToolTest, ResetCategories) {
  // Test starting all debugging.
  EXPECT_CALL(mock_executor_, RestartUpstartJob(mojom::UpstartJob::kCupsd, _))
      .Times(2);
  EXPECT_CALL(mock_executor_, StopUpstartJob(mojom::UpstartJob::kLorgnette, _))
      .Times(2);
  PrintscanDebugSetCategoriesRequest request;
  request.add_categories(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_PRINTING);
  request.add_categories(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_SCANNING);

  auto response = printscan_tool_->DebugSetCategories(request);

  EXPECT_TRUE(response.result());
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_TRUE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_TRUE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));

  // Test stopping all debugging.
  PrintscanDebugSetCategoriesRequest empty_request;

  response = printscan_tool_->DebugSetCategories(empty_request);

  EXPECT_TRUE(response.result());
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kCupsDebugPath)));
  EXPECT_FALSE(base::PathExists(temp_dir_.GetPath().Append(kIppusbDebugPath)));
  EXPECT_FALSE(
      base::PathExists(temp_dir_.GetPath().Append(kLorgnetteDebugPath)));
}

}  // namespace printscanmgr
