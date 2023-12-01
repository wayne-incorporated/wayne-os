// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/errors/error.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/routines/routine_observer_for_testing.h"
#include "diagnostics/cros_healthd/routines/storage/ufs_lifetime.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using base::test::TestFuture;

inline constexpr char kFakeBsgNodePath[] =
    "sys/devices/pci0000:00/0000:00:12.7/host0/ufs-bsg0";
inline constexpr char kFakeBsgNodePath2[] =
    "sys/devices/pci0000:00/0000:00:1f.0/host0/ufs-bsg0";
inline constexpr char kFakeUfsHealthDescPath[] =
    "sys/devices/pci0000:00/0000:00:12.7/health_descriptor";

class UfsLifetimeRoutineTest : public BaseFileTest {
 protected:
  UfsLifetimeRoutineTest() = default;
  UfsLifetimeRoutineTest(const UfsLifetimeRoutineTest&) = delete;
  UfsLifetimeRoutineTest& operator=(const UfsLifetimeRoutineTest&) = delete;

  void SetUp() {
    SetTestRoot(mock_context_.root_dir());
    routine_ = std::make_unique<UfsLifetimeRoutine>(
        &mock_context_, mojom::UfsLifetimeRoutineArgument::New());
  }

  void SetHealthDescInfo(const std::string& health_desc_path,
                         const std::string& pre_eol_info,
                         const std::string& device_life_time_est_a,
                         const std::string& device_life_time_est_b) {
    SetHealthDescFile(health_desc_path, kUfsHealthDescPreEolInfo, pre_eol_info);
    SetHealthDescFile(health_desc_path, kUfsHealthDescDeviceLifeTimeEstA,
                      device_life_time_est_a);
    SetHealthDescFile(health_desc_path, kUfsHealthDescDeviceLifeTimeEstB,
                      device_life_time_est_b);
  }

  void SetHealthDescFile(const std::string& health_desc_path,
                         const std::string& name,
                         const std::string& content) {
    const base::FilePath& path =
        root_dir().AppendASCII(health_desc_path).AppendASCII(name);
    ASSERT_TRUE(WriteFileAndCreateParentDirs(path, content));
  }

  void CreateDirUnderRoot(const std::string& path) {
    base::CreateDirectory(GetPathUnderRoot(path));
  }

  mojom::RoutineStatePtr RunRoutineAndWaitForExit() {
    TestFuture<void> signal;
    RoutineObserverForTesting observer{signal.GetCallback()};
    routine_->AddObserver(observer.receiver_.BindNewPipeAndPassRemote());
    routine_->SetOnExceptionCallback(
        base::BindOnce([](uint32_t error, const std::string& reason) {
          CHECK(false) << "An exception has occurred when it shouldn't have.";
        }));
    routine_->Start();
    EXPECT_TRUE(signal.Wait());
    return std::move(observer.state_);
  }

  void RunRoutineAndWaitForException(const std::string& expected_reason) {
    TestFuture<uint32_t, const std::string&> future;
    routine_->SetOnExceptionCallback(future.GetCallback());
    routine_->Start();
    EXPECT_EQ(future.Get<std::string>(), expected_reason)
        << "Unexpected reason in exception.";
  }

 private:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<UfsLifetimeRoutine> routine_;
};

// Test that the UFS lifetime routine can run successfully.
TEST_F(UfsLifetimeRoutineTest, RoutineSuccess) {
  CreateDirUnderRoot(kFakeBsgNodePath);
  SetHealthDescInfo(kFakeUfsHealthDescPath, "0x01", "0x0A", "0x0B");

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_TRUE(result->state_union->get_finished()->has_passed);
  const auto& detail =
      result->state_union->get_finished()->detail->get_ufs_lifetime();
  EXPECT_EQ(detail->pre_eol_info, 0x01);
  EXPECT_EQ(detail->device_life_time_est_a, 0x0A);
  EXPECT_EQ(detail->device_life_time_est_b, 0x0B);
}

// Test that the routine fails when Pre EOL info is not normal.
TEST_F(UfsLifetimeRoutineTest, RoutineFailed) {
  CreateDirUnderRoot(kFakeBsgNodePath);
  SetHealthDescInfo(kFakeUfsHealthDescPath, "0x03", "0x01", "0x02");

  mojom::RoutineStatePtr result = RunRoutineAndWaitForExit();
  EXPECT_EQ(result->percentage, 100);
  EXPECT_TRUE(result->state_union->is_finished());
  EXPECT_FALSE(result->state_union->get_finished()->has_passed);
  const auto& detail =
      result->state_union->get_finished()->detail->get_ufs_lifetime();
  EXPECT_EQ(detail->pre_eol_info, 0x03);
  EXPECT_EQ(detail->device_life_time_est_a, 0x01);
  EXPECT_EQ(detail->device_life_time_est_b, 0x02);
}

// Test that the routine raises an exception when the bsg node is missing.
TEST_F(UfsLifetimeRoutineTest, MissingBsgNode) {
  UnsetPath(kFakeBsgNodePath);
  RunRoutineAndWaitForException("Unable to determine a bsg node path");
}

// Test that the routine raises an exception when multiple bsg nodes are
// present.
TEST_F(UfsLifetimeRoutineTest, MultipleBsgNodes) {
  CreateDirUnderRoot(kFakeBsgNodePath);
  CreateDirUnderRoot(kFakeBsgNodePath2);
  RunRoutineAndWaitForException("Unable to determine a bsg node path");
}

// Test that the routine raises an exception when the health descriptor
// directory is missing.
TEST_F(UfsLifetimeRoutineTest, MissingHealthDescDir) {
  CreateDirUnderRoot(kFakeBsgNodePath);
  UnsetPath(kFakeUfsHealthDescPath);
  RunRoutineAndWaitForException(
      "Unable to deduce health descriptor path based on the bsg node path");
}

// Test that the routine raises an exception when any of the health descriptor
// field is not a hex string.
TEST_F(UfsLifetimeRoutineTest, InvalidHealthDescValue) {
  CreateDirUnderRoot(kFakeBsgNodePath);
  SetHealthDescInfo(kFakeUfsHealthDescPath, "NOT A HEX STRING", "0x0A", "0x0B");
  RunRoutineAndWaitForException(
      "Error reading content from UFS health descriptor");
}

}  // namespace
}  // namespace diagnostics
