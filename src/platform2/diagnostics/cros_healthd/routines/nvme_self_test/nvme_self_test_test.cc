// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <debugd/dbus-proxy-mocks.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/nvme_self_test/nvme_self_test.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/debugd_constants.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using OnceStringCallback = base::OnceCallback<void(const std::string& result)>;
using OnceErrorCallback = base::OnceCallback<void(brillo::Error* error)>;
using routine_status = mojom::DiagnosticRoutineStatusEnum;
using ::testing::_;
using ::testing::StrictMock;
using ::testing::WithArg;

// Success message from controller if launching is completed without errors.
constexpr char kStartSuccess[] = "Device self-test started";
constexpr char kNvmeError[] = "NVMe Status:Unknown";

class NvmeSelfTestRoutineTest : public testing::Test {
 protected:
  NvmeSelfTestRoutineTest() = default;
  NvmeSelfTestRoutineTest(const NvmeSelfTestRoutineTest&) = delete;
  NvmeSelfTestRoutineTest& operator=(const NvmeSelfTestRoutineTest&) = delete;

  DiagnosticRoutine* routine() { return routine_.get(); }

  void CreateSelfTestRoutine(const NvmeSelfTestRoutine::SelfTestType& type) {
    routine_ = std::make_unique<NvmeSelfTestRoutine>(&debugd_proxy_, type);
  }

  void RunRoutineStart() {
    DCHECK(routine_);
    routine_->Start();
  }
  void RunRoutineCancel() { routine_->Cancel(); }
  mojom::RoutineUpdatePtr RunRoutinePopulate() {
    mojom::RoutineUpdate update{0, mojo::ScopedHandle(),
                                mojom::RoutineUpdateUnionPtr()};

    routine_->PopulateStatusUpdate(&update, true);
    return mojom::RoutineUpdate::New(update.progress_percent,
                                     std::move(update.output),
                                     std::move(update.routine_update_union));
  }

  StrictMock<org::chromium::debugdProxyMock> debugd_proxy_;

 private:
  std::unique_ptr<NvmeSelfTestRoutine> routine_;
};

// Test that the NvmeSelfTest routine for short-time passes if it starts without
// an error and result from NVMe is passed.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestPass) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // Progress(byte-0): Bits 3:0, 1 means short-time test is in progress.
  // Percent(byte-1): 0x1e for 30%
  const uint8_t kShortSelfTestRunning[] = {0x1, 0x1e, 0x0, 0x0, 0x0, 0x0,
                                           0x0, 0x0,  0x0, 0x0, 0x0, 0x0,
                                           0x0, 0x0,  0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(std::string(std::begin(kShortSelfTestRunning),
                                 std::end(kShortSelfTestRunning)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(RunRoutinePopulate()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             NvmeSelfTestRoutine::kNvmeSelfTestRoutineRunning);

  // Progress(byte-0): Bits 3:0, 0 means test is completed.
  // Status(byte-4): Bits 7:4, 1 for short-time test; Bits 3:0, 0 means passed.
  const uint8_t kShortSelfTestSuccess[] = {0x0, 0x0, 0x0, 0x0, 0x10, 0x0,
                                           0x0, 0x0, 0x0, 0x0, 0x0,  0x0,
                                           0x0, 0x0, 0x0, 0x0};
  nvme_encoded_output.clear();
  base::Base64Encode(std::string(std::begin(kShortSelfTestSuccess),
                                 std::end(kShortSelfTestSuccess)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kPassed,
      NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog[0x0]);
}

// Test that the NvmeSelfTest routine for short-time fails if it starts with
// an error.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestStartError) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kNvmeError);
      }));
  RunRoutineStart();
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeSelfTestRoutine::kNvmeSelfTestRoutineStartError);
}

// Test that the NvmeSelfTest routine for short-time fails if result from NVMe
// is failed.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestError) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  // Progress(byte-0): Bits 3:0, 0 means test is completed.
  // Status(byte-4): Bits 7:4, 1 for short-time test; Bits 3:0, 3 means test
  // failed and error index is 3.
  const uint8_t kShortSelfTestError[] = {0x0, 0x0, 0x0, 0x0, 0x13, 0x0,
                                         0x0, 0x0, 0x0, 0x0, 0x0,  0x0,
                                         0x0, 0x0, 0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(std::string(std::begin(kShortSelfTestError),
                                 std::end(kShortSelfTestError)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kFailed,
      NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog[0x3]);
}

// Test that the NvmeSelfTest routinie for short-time fails if result from NVMe
// is an invalid error.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestInvalidError) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  // Progress(byte-0): Bits 3:0, 0 means test is completed.
  // Status(byte-4): Bits 7:4, 1 for short-time test; Bits 3:0, 0xf means test
  // failed but error index is invalid since total types of error is 9.
  const uint8_t kShortSelfTestInvalidError[] = {0x0, 0x0, 0x0, 0x0, 0x1f, 0x0,
                                                0x0, 0x0, 0x0, 0x0, 0x0,  0x0,
                                                0x0, 0x0, 0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(std::string(std::begin(kShortSelfTestInvalidError),
                                 std::end(kShortSelfTestInvalidError)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kFailed,
      NvmeSelfTestRoutine::kSelfTestRoutineCompleteUnknownStatus);
}

// Test that the NvmeSelfTest routinie for short-time fails if the index of
// type is invalid in result of NVMe..
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestInvalidType) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  // Progress(byte-0): Bits 3:0, 0 means test is completed.
  // Status(byte-4): Bits 7:4, 0xe for vendor specific but not be supported for
  // NvmeSelfTestRoutine; Bits 3:0, 3 means test failed and error index is 3.
  const uint8_t kShortSelfTestInvalidType[] = {0x0, 0x0, 0x0, 0x0, 0xe3, 0x0,
                                               0x0, 0x0, 0x0, 0x0, 0x0,  0x0,
                                               0x0, 0x0, 0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(std::string(std::begin(kShortSelfTestInvalidType),
                                 std::end(kShortSelfTestInvalidType)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeSelfTestRoutine::kNvmeSelfTestRoutineGetProgressFailed);
}

// Test that the NvmeSelfTest routine for short-time fails if debugd return is
// invalid.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestInvalidProgress) {
  // Invalid base64 encoded data. Length of encoded data must divide by 4.
  const char kSelfTestInvalidProgress[] = "AAAAABMEAAAAAAAAAA";

  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(kSelfTestInvalidProgress);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeSelfTestRoutine::kNvmeSelfTestRoutineGetProgressFailed);
}

// Test that the NvmeSelfTest routine for short-time fails if size of return
// data is not equal to required length.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestInvalidProgressLength) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // 8-byte data with valid progress info.
  // Progress(byte-0): Bits 3:0, 1 means short-time test is in progress.
  // Percent(byte-1): 0x1e for 30%
  const uint8_t kEightByteShortSelfTestRunning[] = {0x1, 0x1e, 0x0, 0x0,
                                                    0x0, 0x0,  0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(std::string(std::begin(kEightByteShortSelfTestRunning),
                                 std::end(kEightByteShortSelfTestRunning)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeSelfTestRoutine::kNvmeSelfTestRoutineGetProgressFailed);
}

// Test that the NvmeSelfTest routine for short-time passes if it is cancelled
// successfully.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestCancelPass) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  // Success message from controller if abortion is completed without an error.
  const char kAbortSuccess[] = "Aborting device self-test operation";
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeStopSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kAbortSuccess);
      }));
  RunRoutineCancel();
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kCancelled,
      NvmeSelfTestRoutine::kNvmeSelfTestRoutineCancelled);
}

// Test that the NvmeSelfTest routine for short-time fails if it is cancelled
// with an error.
TEST_F(NvmeSelfTestRoutineTest, ShortSelfTestCancelError) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeStopSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kNvmeError);
      }));
  RunRoutineCancel();
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kError,
      NvmeSelfTestRoutine::kNvmeSelfTestRoutineAbortionError);
}

// Test that the NvmeSelfTest routine for long-time passes if it starts without
// an error and result from NVMe is passed.
TEST_F(NvmeSelfTestRoutineTest, LongSelfTestPass) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunLongSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  // Progress(byte-0): Bits 3:0, 2 means long-time test is in progress.
  // Percent(byte-1): 0x0 for 0%
  const uint8_t kLongSelfTestRunning[] = {0x2, 0x0, 0x0, 0x0, 0x0, 0x0,
                                          0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                                          0x0, 0x0, 0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(std::string(std::begin(kLongSelfTestRunning),
                                 std::end(kLongSelfTestRunning)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(RunRoutinePopulate()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kRunning,
                             NvmeSelfTestRoutine::kNvmeSelfTestRoutineRunning);

  // Progress(byte-0): Bits 3:0, 0 means test is completed.
  // Status(byte-4): Bits 7:4, 2 for long-time test; Bits 3:0, 0 means passed.
  const uint8_t kLongSelfTestSuccess[] = {0x0, 0x0, 0x0, 0x0, 0x20, 0x0,
                                          0x0, 0x0, 0x0, 0x0, 0x0,  0x0,
                                          0x0, 0x0, 0x0, 0x0};
  nvme_encoded_output.clear();
  base::Base64Encode(std::string(std::begin(kLongSelfTestSuccess),
                                 std::end(kLongSelfTestSuccess)),
                     &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kPassed,
      NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog[0x0]);
}

// Test that the NvmeSelfTest routine for long-time fails if result from NVMe
// is failed.
TEST_F(NvmeSelfTestRoutineTest, LongSelfTestError) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunLongSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  // Progress(byte-0): Bits 3:0, 0 means test is completed.
  // Status(byte-4): Bits 7:4, 2 for long-time test; Bits 3:0, 4 means test
  // failed and error index is 4.
  const uint8_t kLongSelfTestError[] = {0x0, 0x0, 0x0, 0x0, 0x24, 0x0,
                                        0x0, 0x0, 0x0, 0x0, 0x0,  0x0,
                                        0x0, 0x0, 0x0, 0x0};
  std::string nvme_encoded_output;
  base::Base64Encode(
      std::string(std::begin(kLongSelfTestError), std::end(kLongSelfTestError)),
      &nvme_encoded_output);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<3>([&](OnceStringCallback callback) {
        std::move(callback).Run(nvme_encoded_output);
      }));
  VerifyNonInteractiveUpdate(
      RunRoutinePopulate()->routine_update_union,
      mojom::DiagnosticRoutineStatusEnum::kFailed,
      NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog[0x4]);
}

// Tests that the NvmeSelfTest routine fails if debugd returns with an error.
TEST_F(NvmeSelfTestRoutineTest, DebugdError) {
  const char kDebugdErrorMessage[] = "Debugd mock error for testing";
  const brillo::ErrorPtr kError =
      brillo::Error::Create(FROM_HERE, "", "", kDebugdErrorMessage);
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunLongSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<2>([&](OnceErrorCallback callback) {
        std::move(callback).Run(kError.get());
      }));
  RunRoutineStart();
  VerifyNonInteractiveUpdate(RunRoutinePopulate()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kDebugdErrorMessage);
}

// Tests that the NvmeSelfTest routine fails if debugd returns with an error
// while cancelling.
TEST_F(NvmeSelfTestRoutineTest, DebugdErrorForCancelling) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunLongSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  const char kDebugdErrorMessage[] = "Debugd mock error for cancelling";
  const brillo::ErrorPtr kError =
      brillo::Error::Create(FROM_HERE, "", "", kDebugdErrorMessage);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeStopSelfTestOption, _, _, _))
      .WillOnce(WithArg<2>([&](OnceErrorCallback callback) {
        std::move(callback).Run(kError.get());
      }));
  RunRoutineCancel();
  VerifyNonInteractiveUpdate(RunRoutinePopulate()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kDebugdErrorMessage);
}

// Tests that the NvmeSelfTest routine fails if debugd returns with an error
// while getting progress.
TEST_F(NvmeSelfTestRoutineTest, DebugdErrorForGettingProgress) {
  CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunLongSelfTest);
  EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeLongSelfTestOption, _, _, _))
      .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
        std::move(callback).Run(kStartSuccess);
      }));
  RunRoutineStart();

  EXPECT_EQ(routine()->GetStatus(),
            mojom::DiagnosticRoutineStatusEnum::kRunning);

  const char kDebugdErrorMessage[] = "Debugd mock error for getting progress";
  const brillo::ErrorPtr kError =
      brillo::Error::Create(FROM_HERE, "", "", kDebugdErrorMessage);
  EXPECT_CALL(debugd_proxy_,
              NvmeLogAsync(NvmeSelfTestRoutine::kNvmeLogPageId,
                           NvmeSelfTestRoutine::kNvmeLogDataLength,
                           NvmeSelfTestRoutine::kNvmeLogRawBinary, _, _, _))
      .WillOnce(WithArg<4>([&](OnceErrorCallback callback) {
        std::move(callback).Run(kError.get());
      }));
  VerifyNonInteractiveUpdate(RunRoutinePopulate()->routine_update_union,
                             mojom::DiagnosticRoutineStatusEnum::kError,
                             kDebugdErrorMessage);
}

}  // namespace

// TODO(b/214177942): As NvmeSelfTestRoutineTest.RoutineStatusTransition is
// FRIEND_TEST in NvmeSelfTestRoutine, it must *not* be wrapped in anonymous
// namespace. See go/gunitadvanced#testing-private-code. However, using
// FRIEND_TEST is not ideal and should be removed after the routine refactoring.

// Tests that the NvmeSelfTest routine status transition works as expected.
TEST_F(NvmeSelfTestRoutineTest, RoutineStatusTransition) {
  struct TestCase {
    const routine_status source_status;
    const routine_status target_status;
    const bool expected_return;
  };

  constexpr std::array<TestCase, 12> testcases = {
      TestCase{routine_status::kRunning, routine_status::kRunning, true},
      TestCase{routine_status::kRunning, routine_status::kError, true},
      TestCase{routine_status::kRunning, routine_status::kPassed, true},
      TestCase{routine_status::kRunning, routine_status::kFailed, true},
      TestCase{routine_status::kRunning, routine_status::kCancelling, true},
      TestCase{routine_status::kCancelling, routine_status::kError, true},
      TestCase{routine_status::kCancelling, routine_status::kCancelled, true},
      TestCase{routine_status::kCancelling, routine_status::kRunning, false},
      TestCase{routine_status::kPassed, routine_status::kRunning, false},
      TestCase{routine_status::kFailed, routine_status::kRunning, false},
      TestCase{routine_status::kError, routine_status::kRunning, false},
      TestCase{routine_status::kCancelled, routine_status::kRunning, false},
  };

  for (const auto& testcase : testcases) {
    CreateSelfTestRoutine(NvmeSelfTestRoutine::kRunShortSelfTest);
    EXPECT_CALL(debugd_proxy_, NvmeAsync(kNvmeShortSelfTestOption, _, _, _))
        .WillOnce(WithArg<1>([&](OnceStringCallback callback) {
          std::move(callback).Run(kStartSuccess);
        }));
    RunRoutineStart();
    EXPECT_EQ(routine()->GetStatus(),
              mojom::DiagnosticRoutineStatusEnum::kRunning);
    EXPECT_TRUE(
        reinterpret_cast<NvmeSelfTestRoutine*>(routine())
            ->UpdateStatusWithProgressPercent(testcase.source_status, 100, ""));
    EXPECT_EQ(
        reinterpret_cast<NvmeSelfTestRoutine*>(routine())
            ->UpdateStatusWithProgressPercent(testcase.target_status, 100, ""),
        testcase.expected_return);
  }
}

}  // namespace diagnostics
