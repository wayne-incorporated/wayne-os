// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/values.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/callback_helpers.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/system/handle.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/executor/utils/fake_process_control.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/routine_adapter.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/memory_v2.h"
#include "diagnostics/cros_healthd/routines/routine_observer_for_testing.h"
#include "diagnostics/cros_healthd/routines/routine_service.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ash::cros_healthd::mojom;
using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;
using ::testing::WithArgs;

// Location of files containing test data (fake memtester output).
constexpr char kTestDataRoot[] =
    "cros_healthd/routines/memory_and_cpu/testdata";

#if ULONG_MAX == 4294967295UL
constexpr int kBitFlipPercentage = 57;
#elif ULONG_MAX == 18446744073709551615ULL
constexpr int kBitFlipPercentage = 42;
#endif

class MemoryRoutineV2TestBase : public BaseFileTest {
 protected:
  MemoryRoutineV2TestBase() = default;
  MemoryRoutineV2TestBase(const MemoryRoutineV2TestBase&) = delete;
  MemoryRoutineV2TestBase& operator=(const MemoryRoutineV2TestBase&) = delete;

  void SetUp() override {
    SetTestRoot(mock_context_.root_dir());
    SetMockMemoryInfo(
        "MemTotal:        3906320 kB\n"
        "MemFree:         2873180 kB\n"
        "MemAvailable:    2878980 kB\n");
    SetExecutorResponse();
  }

  void SetMockMemoryInfo(const std::string& info) {
    SetFile({"proc", "meminfo"}, info);
  }

  std::set<mojom::MemtesterTestItemEnum> GetExpectedMemtesterTests(
      std::set<mojom::MemtesterTestItemEnum> unexpected_subtests) {
    std::set<mojom::MemtesterTestItemEnum> expected_subtests;
    for (int i = static_cast<int>(mojom::MemtesterTestItemEnum::kUnknown) + 1;
         i <= static_cast<int>(mojom::MemtesterTestItemEnum::kMaxValue); i++) {
      auto subtest = static_cast<mojom::MemtesterTestItemEnum>(i);
      if (!unexpected_subtests.count(subtest)) {
        expected_subtests.insert(subtest);
      }
    }
    return expected_subtests;
  }

  // Sets the mock executor response by binding receiver and storing how much
  // memory is being tested.
  void SetExecutorResponse() {
    EXPECT_CALL(*mock_context_.mock_executor(), RunMemtesterV2(_, _))
        .WillRepeatedly(WithArgs<0, 1>(Invoke(
            [=](uint32_t testing_mem_kib,
                mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
                    receiver) mutable {
              fake_process_control_.BindReceiver(std::move(receiver));
              received_testing_mem_kib_ = testing_mem_kib;
            })));
  }

  void SetExecutorOutput(const std::string& output) {
    fake_process_control_.SetStdoutFileContent(output);
    fake_process_control_.SetStderrFileContent(output);
  }

  void SetExecutorOutputFromTestFile(const std::string& file_name) {
    std::string output;
    EXPECT_TRUE(base::ReadFileToString(
        base::FilePath(kTestDataRoot).Append(file_name), &output));
    fake_process_control_.SetStdoutFileContent(output);
    fake_process_control_.SetStderrFileContent(output);
  }

  void SetExecutorReturnCode(int return_code) {
    fake_process_control_.SetReturnCode(return_code);
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  MockContext mock_context_;
  FakeProcessControl fake_process_control_;
  int received_testing_mem_kib_ = -1;
};

class MemoryRoutineV2AdapterTest : public MemoryRoutineV2TestBase {
 protected:
  MemoryRoutineV2AdapterTest() = default;
  MemoryRoutineV2AdapterTest(const MemoryRoutineV2AdapterTest&) = delete;
  MemoryRoutineV2AdapterTest& operator=(const MemoryRoutineV2AdapterTest&) =
      delete;

  void SetUp() {
    MemoryRoutineV2TestBase::SetUp();
    routine_adapter_ =
        std::make_unique<RoutineAdapter>(mojom::RoutineArgument::Tag::kMemory);
    routine_service_.CreateRoutine(
        mojom::RoutineArgument::NewMemory(
            mojom::MemoryRoutineArgument::New(std::nullopt)),
        routine_adapter_->BindNewPipeAndPassReceiver());
  }

  // A utility function to flush the routine control and process control.
  void FlushAdapter() {
    // Flush the routine for all request to executor through process
    // control.
    routine_adapter_->FlushRoutineControlForTesting();
    // No need to continue if there is an error and the receiver has
    // disconnected already.
    if (fake_process_control_.IsConnected()) {
      // Flush the process control to return all request to routine.
      fake_process_control_.receiver().FlushForTesting();
      // Flush the routine control once more to run any callbacks called by
      // fake_process_control.
      routine_adapter_->FlushRoutineControlForTesting();
    }
  }

  // A utility function to parse a mojo::ScopedHandle into a base::Value::Dict.
  base::Value::Dict GetJsonFromOutput(mojo::ScopedHandle output) {
    EXPECT_TRUE(output->is_valid());
    auto shm_mapping =
        diagnostics::GetReadOnlySharedMemoryMappingFromMojoHandle(
            std::move(output));
    EXPECT_TRUE(shm_mapping.IsValid());

    auto json = base::JSONReader::Read(std::string(
        shm_mapping.GetMemoryAs<const char>(), shm_mapping.mapped_size()));
    EXPECT_TRUE(json.has_value());
    EXPECT_TRUE(json.value().is_dict());
    return std::move(json.value().GetDict());
  }

  mojom::MemtesterTestItemEnum SubtestNameToEnum(
      const std::string& subtest_name) {
    if (subtest_name == "StuckAddress") {
      return mojom::MemtesterTestItemEnum::kStuckAddress;
    } else if (subtest_name == "CompareAND") {
      return mojom::MemtesterTestItemEnum::kCompareAND;
    } else if (subtest_name == "CompareDIV") {
      return mojom::MemtesterTestItemEnum::kCompareDIV;
    } else if (subtest_name == "CompareMUL") {
      return mojom::MemtesterTestItemEnum::kCompareMUL;
    } else if (subtest_name == "CompareOR") {
      return mojom::MemtesterTestItemEnum::kCompareOR;
    } else if (subtest_name == "CompareSUB") {
      return mojom::MemtesterTestItemEnum::kCompareSUB;
    } else if (subtest_name == "CompareXOR") {
      return mojom::MemtesterTestItemEnum::kCompareXOR;
    } else if (subtest_name == "SequentialIncrement") {
      return mojom::MemtesterTestItemEnum::kSequentialIncrement;
    } else if (subtest_name == "BitFlip") {
      return mojom::MemtesterTestItemEnum::kBitFlip;
    } else if (subtest_name == "BitSpread") {
      return mojom::MemtesterTestItemEnum::kBitSpread;
    } else if (subtest_name == "BlockSequential") {
      return mojom::MemtesterTestItemEnum::kBlockSequential;
    } else if (subtest_name == "Checkerboard") {
      return mojom::MemtesterTestItemEnum::kCheckerboard;
    } else if (subtest_name == "RandomValue") {
      return mojom::MemtesterTestItemEnum::kRandomValue;
    } else if (subtest_name == "SolidBits") {
      return mojom::MemtesterTestItemEnum::kSolidBits;
    } else if (subtest_name == "WalkingOnes") {
      return mojom::MemtesterTestItemEnum::kWalkingOnes;
    } else if (subtest_name == "WalkingZeroes") {
      return mojom::MemtesterTestItemEnum::kWalkingZeroes;
    } else if (subtest_name == "8-bitWrites") {
      return mojom::MemtesterTestItemEnum::k8BitWrites;
    } else if (subtest_name == "16-bitWrites") {
      return mojom::MemtesterTestItemEnum::k16BitWrites;
    }
    EXPECT_TRUE(false) << "Subtest name not recognized: " << subtest_name;
    return mojom::MemtesterTestItemEnum::kUnknown;
  }

  void GetSubtestStatus(const base::Value::Dict& json,
                        std::set<mojom::MemtesterTestItemEnum>& passed_tests,
                        std::set<mojom::MemtesterTestItemEnum>& failed_tests) {
    auto result_details = json.FindDict("resultDetails");
    EXPECT_TRUE(result_details != nullptr);
    auto subtests = result_details->FindDict("subtests");
    EXPECT_TRUE(subtests != nullptr);
    for (const auto& [subtest_name, subtest_status] : *subtests) {
      if (subtest_status == "ok") {
        passed_tests.insert(SubtestNameToEnum(subtest_name));
      } else {
        failed_tests.insert(SubtestNameToEnum(subtest_name));
      }
    }
  }

  mojom::RoutineUpdatePtr GetUpdate() {
    mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
    routine_adapter_->PopulateStatusUpdate(update.get(), true);
    return update;
  }

  RoutineService routine_service_{&mock_context_};
  std::unique_ptr<RoutineAdapter> routine_adapter_;
};

class MemoryRoutineV2Test : public MemoryRoutineV2TestBase {
 protected:
  MemoryRoutineV2Test() = default;
  MemoryRoutineV2Test(const MemoryRoutineV2Test&) = delete;
  MemoryRoutineV2Test& operator=(const MemoryRoutineV2Test&) = delete;

  void SetUp() {
    MemoryRoutineV2TestBase::SetUp();
    routine_ = std::make_unique<MemoryRoutineV2>(
        &mock_context_, mojom::MemoryRoutineArgument::New(std::nullopt));
  }

  mojom::RoutineStatePtr RunRoutineAndWaitForExit() {
    base::RunLoop run_loop;
    routine_->SetOnExceptionCallback(
        base::BindOnce([](uint32_t error, const std::string& reason) {
          CHECK(false) << "An exception has occurred when it shouldn't have.";
        }));
    RoutineObserverForTesting observer{run_loop.QuitClosure()};
    routine_->AddObserver(observer.receiver_.BindNewPipeAndPassRemote());
    routine_->Start();
    run_loop.Run();
    return std::move(observer.state_);
  }

  void RunRoutineAndWaitForException() {
    base::RunLoop run_loop;
    routine_->SetOnExceptionCallback(base::BindLambdaForTesting(
        [&](uint32_t error, const std::string& reason) { run_loop.Quit(); }));
    routine_->Start();
    run_loop.Run();
  }

  std::set<mojom::MemtesterTestItemEnum> VectorToSet(
      std::vector<mojom::MemtesterTestItemEnum> v) {
    return std::set<mojom::MemtesterTestItemEnum>(v.begin(), v.end());
  }

  std::unique_ptr<MemoryRoutineV2> routine_;
};

// Test that the memory routine can run successfully.
TEST_F(MemoryRoutineV2Test, RoutineSuccess) {
  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_TRUE(result->state_union->get_finished()->has_passed);
  std::set<mojom::MemtesterTestItemEnum> expected_failed{};
  std::set<mojom::MemtesterTestItemEnum> expected_passed =
      GetExpectedMemtesterTests(expected_failed);
  EXPECT_EQ(VectorToSet(result->state_union->get_finished()
                            ->detail->get_memory()
                            ->result->passed_items),
            expected_passed);
  EXPECT_EQ(VectorToSet(result->state_union->get_finished()
                            ->detail->get_memory()
                            ->result->failed_items),
            expected_failed);
}

// Test that we can run a routine successfully using routine adapter API.
TEST_F(MemoryRoutineV2AdapterTest, RoutineSuccess) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  routine_adapter_->Start();
  FlushAdapter();
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 100);
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kPassed);
}

// Test that the memory routine handles the parsing error.
TEST_F(MemoryRoutineV2Test, RoutineParseError) {
  SetMockMemoryInfo("Incorrectly formatted meminfo contents.\n");
  RunRoutineAndWaitForException();
}

// Test that the memory routine handles the parsing error.
TEST_F(MemoryRoutineV2AdapterTest, RoutineParseError) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  SetMockMemoryInfo("Incorrectly formatted meminfo contents.\n");

  routine_adapter_->Start();
  FlushAdapter();
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kError);
}

// Test that the memory routine handles when there is not much memory left.
TEST_F(MemoryRoutineV2Test, RoutineLessThan500MBMemory) {
  // MemAvailable less than 500 MiB.
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         2873180 kB\n"
      "MemAvailable:    278980 kB\n");
  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_TRUE(result->state_union->get_finished()->has_passed);
  // If the available memory is too little, run with the minimum memory
  // memtester allows (4 Kib).
  EXPECT_EQ(received_testing_mem_kib_, 4);
}

// Test that the memory routine handles when there is not much memory left.
TEST_F(MemoryRoutineV2AdapterTest, RoutineLessThan500MBMemory) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  // MemAvailable less than 500 MiB.
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         2873180 kB\n"
      "MemAvailable:    278980 kB\n");
  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  routine_adapter_->Start();
  FlushAdapter();
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 100);
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kPassed);
  // If the available memory is too little, run with the minimum memory
  // memtester allows (4 Kib).
  EXPECT_EQ(received_testing_mem_kib_, 4);
}

// Test that the memory routine handles when there is less than 4KB memory
TEST_F(MemoryRoutineV2Test, RoutineNotEnoughMemory) {
  // MemAvailable less than 4 KB.
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         2873180 kB\n"
      "MemAvailable:    3 kB\n");
  RunRoutineAndWaitForException();
}

// Test that the memory routine handles when there is less than 4KB memory
TEST_F(MemoryRoutineV2AdapterTest, RoutineNotEnoughMemory) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  // MemAvailable less than 4 KB.
  SetMockMemoryInfo(
      "MemTotal:        3906320 kB\n"
      "MemFree:         2873180 kB\n"
      "MemAvailable:    3 kB\n");

  routine_adapter_->Start();
  FlushAdapter();
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kError);
}

// Test that the memory routine handles the memtester binary failing to run.
TEST_F(MemoryRoutineV2Test, MemtesterFailedToRunError) {
  SetExecutorOutput("");
  SetExecutorReturnCode(MemtesterErrorCodes::kAllocatingLockingInvokingError);
  RunRoutineAndWaitForException();
}

// Test that the memory routine handles the memtester binary failing to run.
TEST_F(MemoryRoutineV2AdapterTest, MemtesterFailedToRunError) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  SetExecutorOutput("");
  SetExecutorReturnCode(MemtesterErrorCodes::kAllocatingLockingInvokingError);

  routine_adapter_->Start();
  FlushAdapter();
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kError);
}

// Test that the memory routine handles a stuck address failure.
TEST_F(MemoryRoutineV2Test, StuckAddressFailure) {
  SetExecutorOutputFromTestFile("stuck_address_failed_output");
  SetExecutorReturnCode(MemtesterErrorCodes::kStuckAddressTestError);

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
  std::set<mojom::MemtesterTestItemEnum> expected_failed{
      mojom::MemtesterTestItemEnum::kStuckAddress};
  std::set<mojom::MemtesterTestItemEnum> expected_passed =
      GetExpectedMemtesterTests(expected_failed);
  EXPECT_EQ(VectorToSet(result->state_union->get_finished()
                            ->detail->get_memory()
                            ->result->passed_items),
            expected_passed);
  EXPECT_EQ(VectorToSet(result->state_union->get_finished()
                            ->detail->get_memory()
                            ->result->failed_items),
            expected_failed);
}

// Test that the memory routine handles a stuck address failure.
TEST_F(MemoryRoutineV2AdapterTest, StuckAddressFailure) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  SetExecutorOutputFromTestFile("stuck_address_failed_output");
  SetExecutorReturnCode(MemtesterErrorCodes::kStuckAddressTestError);

  routine_adapter_->Start();
  std::set<mojom::MemtesterTestItemEnum> expected_failed{
      mojom::MemtesterTestItemEnum::kStuckAddress};
  std::set<mojom::MemtesterTestItemEnum> expected_passed =
      GetExpectedMemtesterTests(expected_failed);
  FlushAdapter();
  update = GetUpdate();

  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kFailed);
  base::Value::Dict json = GetJsonFromOutput(std::move(update->output));
  std::set<mojom::MemtesterTestItemEnum> passed, failed;
  GetSubtestStatus(json, passed, failed);
  EXPECT_EQ(passed, expected_passed);
  EXPECT_EQ(failed, expected_failed);
}

// Test that the memory routine handles multiple test failure.
TEST_F(MemoryRoutineV2Test, MultipleTestFailure) {
  SetExecutorOutputFromTestFile("stuck_address_and_bit_flip_failed_output");
  SetExecutorReturnCode(MemtesterErrorCodes::kStuckAddressTestError |
                        MemtesterErrorCodes::kOtherTestError);

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
  std::set<mojom::MemtesterTestItemEnum> expected_failed{
      mojom::MemtesterTestItemEnum::kStuckAddress,
      mojom::MemtesterTestItemEnum::kBitFlip};
  std::set<mojom::MemtesterTestItemEnum> expected_passed =
      GetExpectedMemtesterTests(expected_failed);
  EXPECT_EQ(VectorToSet(result->state_union->get_finished()
                            ->detail->get_memory()
                            ->result->passed_items),
            expected_passed);
  EXPECT_EQ(VectorToSet(result->state_union->get_finished()
                            ->detail->get_memory()
                            ->result->failed_items),
            expected_failed);
}

// Test that the memory routine handles a multiple test failure.
TEST_F(MemoryRoutineV2AdapterTest, MultipleTestFailure) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  SetExecutorOutputFromTestFile("stuck_address_and_bit_flip_failed_output");
  SetExecutorReturnCode(MemtesterErrorCodes::kStuckAddressTestError |
                        MemtesterErrorCodes::kOtherTestError);

  routine_adapter_->Start();
  std::set<mojom::MemtesterTestItemEnum> expected_failed{
      mojom::MemtesterTestItemEnum::kStuckAddress,
      mojom::MemtesterTestItemEnum::kBitFlip};
  std::set<mojom::MemtesterTestItemEnum> expected_passed =
      GetExpectedMemtesterTests(expected_failed);
  FlushAdapter();
  update = GetUpdate();
  EXPECT_TRUE(update->routine_update_union->is_noninteractive_update());
  EXPECT_EQ(update->routine_update_union->get_noninteractive_update()->status,
            mojom::DiagnosticRoutineStatusEnum::kFailed);
  base::Value::Dict json = GetJsonFromOutput(std::move(update->output));
  std::set<mojom::MemtesterTestItemEnum> passed, failed;
  GetSubtestStatus(json, passed, failed);
  EXPECT_EQ(passed, expected_passed);
  EXPECT_EQ(failed, expected_failed);
}

// Test that the memory routine handles setting a max_testing_mem_kib value.
TEST_F(MemoryRoutineV2Test, SettingMaxTestingMemKibValue) {
  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  routine_ = std::make_unique<MemoryRoutineV2>(
      &mock_context_, mojom::MemoryRoutineArgument::New(1000));
  RunRoutineAndWaitForExit();
  EXPECT_EQ(received_testing_mem_kib_, 1000);
}

// Test that the memory routine handles setting a max_testing_mem_kib value.
TEST_F(MemoryRoutineV2AdapterTest, SettingMaxTestingMemKibValue) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  routine_adapter_ =
      std::make_unique<RoutineAdapter>(mojom::RoutineArgument::Tag::kMemory);
  routine_service_.CreateRoutine(
      mojom::RoutineArgument::NewMemory(
          mojom::MemoryRoutineArgument::New(1000)),
      routine_adapter_->BindNewPipeAndPassReceiver());
  routine_adapter_->Start();
  FlushAdapter();
  EXPECT_EQ(received_testing_mem_kib_, 1000);
}

// Test that the memory routine is able to detect incremental progress.
TEST_F(MemoryRoutineV2Test, IncrementalProgress) {
  std::string progress_0_output, progress_bit_flip_output,
      all_test_passed_output;
  EXPECT_TRUE(base::ReadFileToString(
      base::FilePath(kTestDataRoot).Append("progress_0_output"),
      &progress_0_output));
  EXPECT_TRUE(base::ReadFileToString(
      base::FilePath(kTestDataRoot).Append("progress_bit_flip_output"),
      &progress_bit_flip_output));
  EXPECT_TRUE(base::ReadFileToString(
      base::FilePath(kTestDataRoot).Append("all_test_passed_output"),
      &all_test_passed_output));
  // Check that the output are strictly increasing by checking if the outputs
  // are prefix of each other.
  EXPECT_TRUE(base::StartsWith(progress_bit_flip_output, progress_0_output,
                               base::CompareCase::SENSITIVE));
  EXPECT_TRUE(base::StartsWith(all_test_passed_output, progress_bit_flip_output,
                               base::CompareCase::SENSITIVE));

  SetExecutorOutputFromTestFile("progress_0_output");

  routine_->SetOnExceptionCallback(
      base::BindOnce([](uint32_t error, const std::string& reason) {
        CHECK(false) << "An exception has occurred when it shouldn't have.";
      }));
  RoutineObserverForTesting observer{base::DoNothing()};
  routine_->AddObserver(observer.receiver_.BindNewPipeAndPassRemote());
  routine_->Start();

  // Fast forward for observer to update percentage.
  task_environment_.FastForwardBy(kMemoryRoutineUpdatePeriod);
  EXPECT_EQ(observer.state_->percentage, 0);

  SetExecutorOutputFromTestFile("progress_bit_flip_output");

  // Fast forward for observer to update percentage.
  task_environment_.FastForwardBy(kMemoryRoutineUpdatePeriod);
  EXPECT_EQ(observer.state_->percentage, kBitFlipPercentage);

  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  // Fast forward for observer to set finished state.
  task_environment_.FastForwardBy(kMemoryRoutineUpdatePeriod);
  EXPECT_EQ(observer.state_->percentage, 100);
}

// Test that the memory routine is able to detect incremental progress.
TEST_F(MemoryRoutineV2AdapterTest, IncrementalProgress) {
  mojom::RoutineUpdatePtr update = mojom::RoutineUpdate::New();
  std::string progress_0_output, progress_bit_flip_output,
      all_test_passed_output;
  EXPECT_TRUE(base::ReadFileToString(
      base::FilePath(kTestDataRoot).Append("progress_0_output"),
      &progress_0_output));
  EXPECT_TRUE(base::ReadFileToString(
      base::FilePath(kTestDataRoot).Append("progress_bit_flip_output"),
      &progress_bit_flip_output));
  EXPECT_TRUE(base::ReadFileToString(
      base::FilePath(kTestDataRoot).Append("all_test_passed_output"),
      &all_test_passed_output));
  // Check that the output are strictly increasing by checking if the outputs
  // are prefix of each other.
  EXPECT_TRUE(base::StartsWith(progress_bit_flip_output, progress_0_output,
                               base::CompareCase::SENSITIVE));
  EXPECT_TRUE(base::StartsWith(all_test_passed_output, progress_bit_flip_output,
                               base::CompareCase::SENSITIVE));

  SetExecutorOutputFromTestFile("progress_0_output");

  routine_adapter_->Start();

  // Fast forward for observer to update percentage.
  task_environment_.FastForwardBy(kMemoryRoutineUpdatePeriod);
  FlushAdapter();
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 0);

  SetExecutorOutputFromTestFile("progress_bit_flip_output");

  // Fast forward for observer to update percentage.
  task_environment_.FastForwardBy(kMemoryRoutineUpdatePeriod);
  FlushAdapter();
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, kBitFlipPercentage);

  SetExecutorOutputFromTestFile("all_test_passed_output");
  SetExecutorReturnCode(EXIT_SUCCESS);

  // Fast forward for observer to set finished state.
  task_environment_.FastForwardBy(kMemoryRoutineUpdatePeriod);

  FlushAdapter();
  update = GetUpdate();
  EXPECT_EQ(update->progress_percent, 100);
}

}  // namespace
}  // namespace diagnostics
