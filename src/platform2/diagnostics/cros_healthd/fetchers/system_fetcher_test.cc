// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/system_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/system_fetcher_constants.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/utils/mojo_type_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;

template <typename T>
std::optional<std::string> GetMockValue(const T& value) {
  return value;
}

std::optional<std::string> GetMockValue(const mojom::NullableUint64Ptr& ptr) {
  if (ptr)
    return base::NumberToString(ptr->value);
  return std::nullopt;
}

class SystemUtilsTest : public BaseFileTest {
 protected:
  SystemUtilsTest() = default;
  SystemUtilsTest(const SystemUtilsTest&) = delete;
  SystemUtilsTest& operator=(const SystemUtilsTest&) = delete;

  void SetUp() override {
    SetTestRoot(mock_context_.root_dir());

    expected_system_info_ = mojom::SystemInfo::New();
    auto& vpd_info = expected_system_info_->vpd_info;
    vpd_info = mojom::VpdInfo::New();
    vpd_info->activate_date = "2020-40";
    vpd_info->mfg_date = "2019-01-01";
    vpd_info->model_name = "XX ModelName 007 XY";
    vpd_info->region = "us";
    vpd_info->serial_number = "8607G03EDF";
    vpd_info->sku_number = "ABCD&^A";
    vpd_info->oem_name = "FooOEM-VPD";
    auto& dmi_info = expected_system_info_->dmi_info;
    dmi_info = mojom::DmiInfo::New();
    dmi_info->bios_vendor = "Google";
    dmi_info->bios_version = "Google_BoardName.12200.68.0";
    dmi_info->board_name = "BoardName";
    dmi_info->board_vendor = "Google";
    dmi_info->board_version = "rev1234";
    dmi_info->chassis_vendor = "Google";
    dmi_info->chassis_type = mojom::NullableUint64::New(9);
    dmi_info->product_family = "FooFamily";
    dmi_info->product_name = "BarProductName";
    dmi_info->product_version = "rev1234";
    dmi_info->sys_vendor = "Google";
    auto& os_info = expected_system_info_->os_info;
    os_info = mojom::OsInfo::New();
    os_info->code_name = "CodeName";
    os_info->marketing_name = "Latitude 1234 Chromebook Enterprise";
    os_info->oem_name = "FooOEM";
    os_info->boot_mode = mojom::BootMode::kCrosSecure;
    os_info->efi_platform_size = mojom::OsInfo::EfiPlatformSize::kUnknown;
    auto& os_version = os_info->os_version;
    os_version = mojom::OsVersion::New();
    os_version->release_milestone = "87";
    os_version->build_number = "13544";
    os_version->branch_number = "59";
    os_version->patch_number = "0";
    os_version->release_channel = "stable-channel";
    auto& psr_info = expected_system_info_->psr_info;
    psr_info = mojom::PsrInfo::New();
    psr_info->log_state = mojom::PsrInfo::LogState::kStarted;
    psr_info->uuid = "ed6703fa-d312-4e8b-9ddd-2155bb2dee65";
    psr_info->upid = "ok6703fa-d312-4e8b-9ddd-2155bb2dee65";
    psr_info->log_start_date = 163987200;
    psr_info->oem_name = "Panasonic";
    psr_info->oem_make = "Toughbook";
    psr_info->oem_model = "55";
    psr_info->manufacture_country = "United States";
    psr_info->oem_data = "None";
    psr_info->uptime_seconds = 30233443;
    psr_info->s5_counter = 3;
    psr_info->s4_counter = 2;
    psr_info->s3_counter = 1;
    psr_info->warm_reset_counter = 0;
    auto event = mojom::PsrEvent::New();
    event->type = mojom::PsrEvent::EventType::kLogStart;
    event->time = 163987200;
    event->data = 342897977;
    psr_info->events.push_back(event.Clone());
    event->type = mojom::PsrEvent::EventType::kPrtcFailure;
    event->time = 453987200;
    event->data = 643897977;
    psr_info->events.push_back(event.Clone());
    SetSystemInfo(expected_system_info_);
    SetHasSkuNumber(true);
  }

  void SetSystemInfo(const mojom::SystemInfoPtr& system_info) {
    SetVpdInfo(system_info->vpd_info);
    SetDmiInfo(system_info->dmi_info);
    SetOsInfo(system_info->os_info);
  }

  void SetVpdInfo(const mojom::VpdInfoPtr& vpd_info) {
    const auto& ro = kRelativePathVpdRo;
    const auto& rw = kRelativePathVpdRw;
    if (vpd_info.is_null()) {
      // Delete the whole vpd dir.
      UnsetPath(base::FilePath(ro).DirName());
      return;
    }
    SetMockFile({rw, kFileNameActivateDate}, vpd_info->activate_date);
    SetMockFile({ro, kFileNameMfgDate}, vpd_info->mfg_date);
    SetMockFile({ro, kFileNameModelName}, vpd_info->model_name);
    SetMockFile({ro, kFileNameRegion}, vpd_info->region);
    SetMockFile({ro, kFileNameSerialNumber}, vpd_info->serial_number);
    SetMockFile({ro, kFileNameSkuNumber}, vpd_info->sku_number);
    SetMockFile({ro, kFileNameOemName}, vpd_info->oem_name);
  }

  void SetDmiInfo(const mojom::DmiInfoPtr& dmi_info) {
    const auto& dmi = kRelativePathDmiInfo;
    if (dmi_info.is_null()) {
      UnsetPath(dmi);
      return;
    }
    SetMockFile({dmi, kFileNameBiosVendor}, dmi_info->bios_vendor);
    SetMockFile({dmi, kFileNameBiosVersion}, dmi_info->bios_version);
    SetMockFile({dmi, kFileNameBoardName}, dmi_info->board_name);
    SetMockFile({dmi, kFileNameBoardVendor}, dmi_info->board_vendor);
    SetMockFile({dmi, kFileNameBoardVersion}, dmi_info->board_version);
    SetMockFile({dmi, kFileNameChassisVendor}, dmi_info->chassis_vendor);
    SetMockFile({dmi, kFileNameChassisType}, dmi_info->chassis_type);
    SetMockFile({dmi, kFileNameProductFamily}, dmi_info->product_family);
    SetMockFile({dmi, kFileNameProductName}, dmi_info->product_name);
    SetMockFile({dmi, kFileNameProductVersion}, dmi_info->product_version);
    SetMockFile({dmi, kFileNameSysVendor}, dmi_info->sys_vendor);
  }

  void SetOsInfo(const mojom::OsInfoPtr& os_info) {
    ASSERT_FALSE(os_info.is_null());
    mock_context_.fake_system_config()->SetMarketingName(
        os_info->marketing_name);
    mock_context_.fake_system_config()->SetOemName(os_info->oem_name);
    mock_context_.fake_system_config()->SetCodeName(os_info->code_name);
    SetOsVersion(os_info->os_version);
    SetBootModeInProcCmd(os_info->boot_mode);
  }

  void SetOsVersion(const mojom::OsVersionPtr& os_version) {
    PopulateLsbRelease(base::StringPrintf(
        "CHROMEOS_RELEASE_CHROME_MILESTONE=%s\n"
        "CHROMEOS_RELEASE_BUILD_NUMBER=%s\n"
        "CHROMEOS_RELEASE_BRANCH_NUMBER=%s\n"
        "CHROMEOS_RELEASE_PATCH_NUMBER=%s\n"
        "CHROMEOS_RELEASE_TRACK=%s\n",
        os_version->release_milestone.c_str(), os_version->build_number.c_str(),
        os_version->branch_number.value().c_str(),
        os_version->patch_number.c_str(), os_version->release_channel.c_str()));
  }

  void SetBootModeInProcCmd(const mojom::BootMode& boot_mode) {
    std::optional<std::string> proc_cmd;
    switch (boot_mode) {
      case mojom::BootMode::kCrosSecure:
        proc_cmd = "Foo Bar=1 cros_secure Foo Bar=1";
        break;
      case mojom::BootMode::kCrosEfi:
        proc_cmd = "Foo Bar=1 cros_efi Foo Bar=1";
        break;
      case mojom::BootMode::kCrosEfiSecure:
        proc_cmd = "Foo Bar=1 cros_efi Foo Bar=1";
        break;
      case mojom::BootMode::kCrosLegacy:
        proc_cmd = "Foo Bar=1 cros_legacy Foo Bar=1";
        break;
      case mojom::BootMode::kUnknown:
        proc_cmd = "Foo Bar=1 Foo Bar=1";
        break;
    }
    SetMockFile(kFilePathProcCmdline, proc_cmd);
  }

  void SetMockExecutorReadFile(mojom::Executor::File file_enum,
                               const std::string& content) {
    // Set the mock executor response.
    EXPECT_CALL(*mock_executor(), ReadFile(file_enum, _))
        .WillOnce(WithArg<1>(
            Invoke([content](mojom::Executor::ReadFileCallback callback) {
              std::move(callback).Run(content);
            })));
  }

  void SetPsrInfoResponse(const std::optional<std::string>& err) {
    EXPECT_CALL(*mock_executor(), GetPsr(_))
        .WillOnce(
            WithArg<0>(Invoke([=](mojom::Executor::GetPsrCallback callback) {
              if (err) {
                std::move(callback).Run(nullptr, err);
                return;
              }
              mojom::PsrInfo result;
              result.log_state = mojom::PsrInfo::LogState::kStarted;
              result.uuid = "ed6703fa-d312-4e8b-9ddd-2155bb2dee65";
              result.upid = "ok6703fa-d312-4e8b-9ddd-2155bb2dee65";
              result.log_start_date = 163987200;
              result.oem_name = "Panasonic";
              result.oem_make = "Toughbook";
              result.oem_model = "55";
              result.manufacture_country = "United States";
              result.oem_data = "None";
              result.uptime_seconds = 30233443;
              result.s5_counter = 3;
              result.s4_counter = 2;
              result.s3_counter = 1;
              result.warm_reset_counter = 0;
              auto event = mojom::PsrEvent::New();
              event->type = mojom::PsrEvent::EventType::kLogStart;
              event->time = 163987200;
              event->data = 342897977;
              result.events.push_back(event.Clone());
              event->type = mojom::PsrEvent::EventType::kPrtcFailure;
              event->time = 453987200;
              event->data = 643897977;
              result.events.push_back(event.Clone());

              std::move(callback).Run(result.Clone(), err);
            })));
  }

  // Sets the mock file with |value|. If the |value| is omitted, deletes the
  // file.
  template <typename T>
  void SetMockFile(const PathType& path, const T& value) {
    auto mock = GetMockValue(value);
    if (mock) {
      SetFile(path, mock.value());
    } else {
      UnsetPath(path);
    }
  }

  void SetHasSkuNumber(bool val) {
    mock_context_.fake_system_config()->SetHasSkuNumber(val);
  }

  void PopulateLsbRelease(const std::string& lsb_release) {
    // Deletes the old instance to release the global lock before creating a new
    // instance.
    chromeos_version_.reset();
    chromeos_version_ = std::make_unique<base::test::ScopedChromeOSVersionInfo>(
        lsb_release, base::Time::Now());
  }

  void ExpectFetchSystemInfo() {
    auto system_result = FetchSystemInfoSync();
    ASSERT_FALSE(system_result.is_null());
    ASSERT_FALSE(system_result->is_error());
    ASSERT_TRUE(system_result->is_system_info());
    auto res = std::move(system_result->get_system_info());
    EXPECT_EQ(res, expected_system_info_)
        << GetDiffString(res, expected_system_info_);
  }

  void ExpectFetchProbeError(const mojom::ErrorType& expected) {
    auto system_result = FetchSystemInfoSync();
    ASSERT_TRUE(system_result->is_error());
    EXPECT_EQ(system_result->get_error()->type, expected);
  }

 protected:
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  mojom::SystemResultPtr FetchSystemInfoSync() {
    base::test::TestFuture<mojom::SystemResultPtr> future;
    FetchSystemInfo(&mock_context_, future.GetCallback());
    return future.Take();
  }

  mojom::SystemInfoPtr expected_system_info_;

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  MockContext mock_context_;
  base::FilePath relative_vpd_rw_dir_;
  base::FilePath relative_vpd_ro_dir_;
  base::FilePath relative_dmi_info_path_;
  std::unique_ptr<base::test::ScopedChromeOSVersionInfo> chromeos_version_;
};

// Template for testing the missing field of vpd/dmi.
#define TEST_MISSING_FIELD(info, field)                \
  TEST_F(SystemUtilsTest, TestNo_##info##_##field) {   \
    expected_system_info_->info->field = std::nullopt; \
    SetSystemInfo(expected_system_info_);              \
    SetPsrInfoResponse(/*err=*/std::nullopt);          \
    ExpectFetchSystemInfo();                           \
  }

TEST_F(SystemUtilsTest, TestFetchSystemInfo) {
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_F(SystemUtilsTest, TestNoVpdDir) {
  expected_system_info_->vpd_info = nullptr;
  SetSystemInfo(expected_system_info_);
  SetHasSkuNumber(true);
  ExpectFetchProbeError(mojom::ErrorType::kFileReadError);

  SetHasSkuNumber(false);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  // Test if the fallback logic triggered by missing OEM name in cros-config
  // works when there's no VPD.
  expected_system_info_->os_info->oem_name = std::nullopt;
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_F(SystemUtilsTest, TestNoSkuNumber) {
  // Sku number file exists.
  SetSystemInfo(expected_system_info_);
  // Ensure that there is no sku number returned even if sku number exists.
  SetHasSkuNumber(false);
  expected_system_info_->vpd_info->sku_number = std::nullopt;
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  // Sku number file doesn't exist.
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  // Sku number file doesn't exist but should have.
  SetHasSkuNumber(true);
  ExpectFetchProbeError(mojom::ErrorType::kFileReadError);
}

TEST_MISSING_FIELD(vpd_info, activate_date);
TEST_MISSING_FIELD(vpd_info, region);
TEST_MISSING_FIELD(vpd_info, mfg_date);
TEST_MISSING_FIELD(vpd_info, serial_number);
TEST_MISSING_FIELD(vpd_info, model_name);
TEST_MISSING_FIELD(vpd_info, oem_name);

TEST_F(SystemUtilsTest, TestNoSysDevicesVirtualDmiId) {
  expected_system_info_->dmi_info = nullptr;
  // Delete the whole directory |kRelativePathDmiInfo|.
  UnsetPath(kRelativePathDmiInfo);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_MISSING_FIELD(dmi_info, bios_vendor);
TEST_MISSING_FIELD(dmi_info, bios_version);
TEST_MISSING_FIELD(dmi_info, board_name);
TEST_MISSING_FIELD(dmi_info, board_vendor);
TEST_MISSING_FIELD(dmi_info, board_version);
TEST_MISSING_FIELD(dmi_info, chassis_vendor);
TEST_MISSING_FIELD(dmi_info, product_family);
TEST_MISSING_FIELD(dmi_info, product_name);
TEST_MISSING_FIELD(dmi_info, product_version);
TEST_MISSING_FIELD(dmi_info, sys_vendor);

TEST_F(SystemUtilsTest, TestNoChassisType) {
  expected_system_info_->dmi_info->chassis_type = nullptr;
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_F(SystemUtilsTest, TestBadChassisType) {
  // Overwrite the contents of |kChassisTypeFileName| with a chassis_type value
  // that cannot be parsed into an unsigned integer.
  std::string bad_chassis_type = "bad chassis type";
  SetMockFile({kRelativePathDmiInfo, kFileNameChassisType}, bad_chassis_type);
  ExpectFetchProbeError(mojom::ErrorType::kParseError);
}

TEST_F(SystemUtilsTest, TestNoOsVersion) {
  PopulateLsbRelease("");
  ExpectFetchProbeError(mojom::ErrorType::kFileReadError);
}

TEST_F(SystemUtilsTest, TestBadOsVersion) {
  PopulateLsbRelease(
      "Milestone\n"
      "CHROMEOS_RELEASE_BUILD_NUMBER=1\n"
      "CHROMEOS_RELEASE_PATCH_NUMBER=2\n"
      "CHROMEOS_RELEASE_TRACK=3\n");
  ExpectFetchProbeError(mojom::ErrorType::kFileReadError);
}

TEST_F(SystemUtilsTest, TestBootMode) {
  expected_system_info_->os_info->boot_mode = mojom::BootMode::kCrosSecure;
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->boot_mode = mojom::BootMode::kCrosEfi;
  // Use string constructor to prevent string truncation from null bytes.
  SetMockExecutorReadFile(mojom::Executor::File::kUEFISecureBootVariable,
                          std::string("\x00\x00\x00\x00\x00", 5));
  SetMockExecutorReadFile(mojom::Executor::File::kUEFIPlatformSize, "");
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->boot_mode = mojom::BootMode::kCrosLegacy;
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->boot_mode = mojom::BootMode::kUnknown;
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->boot_mode = mojom::BootMode::kCrosEfiSecure;
  // Use string constructor to prevent string truncation from null bytes.
  SetMockExecutorReadFile(mojom::Executor::File::kUEFISecureBootVariable,
                          std::string("\x00\x00\x00\x00\x01", 5));
  SetMockExecutorReadFile(mojom::Executor::File::kUEFIPlatformSize, "");
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  // Test that the executor fails to read UEFISecureBoot file content and
  // returns kCrosEfi as default value
  expected_system_info_->os_info->boot_mode = mojom::BootMode::kCrosEfi;
  SetMockExecutorReadFile(mojom::Executor::File::kUEFISecureBootVariable, "");
  SetMockExecutorReadFile(mojom::Executor::File::kUEFIPlatformSize, "");
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_F(SystemUtilsTest, TestEfiPlatformSize) {
  expected_system_info_->os_info->boot_mode = mojom::BootMode::kCrosEfi;
  expected_system_info_->os_info->efi_platform_size =
      mojom::OsInfo::EfiPlatformSize::kUnknown;
  SetMockExecutorReadFile(mojom::Executor::File::kUEFIPlatformSize, "");
  SetMockExecutorReadFile(mojom::Executor::File::kUEFISecureBootVariable,
                          std::string("\x00\x00\x00\x00\x00", 5));
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->efi_platform_size =
      mojom::OsInfo::EfiPlatformSize::k64;
  SetMockExecutorReadFile(mojom::Executor::File::kUEFIPlatformSize, "64");
  SetMockExecutorReadFile(mojom::Executor::File::kUEFISecureBootVariable,
                          std::string("\x00\x00\x00\x00\x00", 5));
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->efi_platform_size =
      mojom::OsInfo::EfiPlatformSize::k32;
  SetMockExecutorReadFile(mojom::Executor::File::kUEFIPlatformSize, "32");
  SetMockExecutorReadFile(mojom::Executor::File::kUEFISecureBootVariable,
                          std::string("\x00\x00\x00\x00\x00", 5));
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_F(SystemUtilsTest, TestOemName) {
  expected_system_info_->os_info->oem_name = "FooOEM";
  expected_system_info_->vpd_info->oem_name = "FooOEM-VPD";
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->oem_name = "FooOEM";
  expected_system_info_->vpd_info->oem_name = "";
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  expected_system_info_->os_info->oem_name = std::nullopt;
  expected_system_info_->vpd_info->oem_name = std::nullopt;
  SetSystemInfo(expected_system_info_);
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();

  // Test the fallback logic triggered by missing OEM name in cros-config.
  expected_system_info_->os_info->oem_name = std::nullopt;
  expected_system_info_->vpd_info->oem_name = "FooOEM-VPD";
  SetSystemInfo(expected_system_info_);
  expected_system_info_->os_info->oem_name = "FooOEM-VPD";
  SetPsrInfoResponse(std::nullopt);
  ExpectFetchSystemInfo();
}

TEST_F(SystemUtilsTest, TestPsrError) {
  SetSystemInfo(expected_system_info_);
  expected_system_info_->psr_info = nullptr;
  SetPsrInfoResponse("GetPsr error");
  ExpectFetchSystemInfo();
}

}  // namespace
}  // namespace diagnostics
