// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <base/test/task_environment.h>
#include <base/test/test_timeouts.h>
#include <chromeos/chromeos-config/libcros_config/fake_cros_config.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/system_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/system_fetcher_constants.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {

namespace {

const std::vector<std::pair<std::string, std::string>> kFiles{
    // VPD files
    {kRelativePathVpdRw, kFileNameActivateDate},
    {kRelativePathVpdRo, kFileNameMfgDate},
    {kRelativePathVpdRo, kFileNameModelName},
    {kRelativePathVpdRo, kFileNameRegion},
    {kRelativePathVpdRo, kFileNameSerialNumber},
    {kRelativePathVpdRo, kFileNameSkuNumber},
    // DMI files
    {kRelativePathDmiInfo, kFileNameBiosVendor},
    {kRelativePathDmiInfo, kFileNameBiosVersion},
    {kRelativePathDmiInfo, kFileNameBoardName},
    {kRelativePathDmiInfo, kFileNameBoardVendor},
    {kRelativePathDmiInfo, kFileNameBoardVersion},
    {kRelativePathDmiInfo, kFileNameChassisType},
    {kRelativePathDmiInfo, kFileNameChassisVendor},
    {kRelativePathDmiInfo, kFileNameProductFamily},
    {kRelativePathDmiInfo, kFileNameProductName},
    {kRelativePathDmiInfo, kFileNameProductVersion},
    {kRelativePathDmiInfo, kFileNameSysVendor},
    // OS info files
    {base::FilePath::kCurrentDirectory, kFilePathProcCmdline}};

void SetUpSystemFiles(const base::FilePath& root_dir,
                      FuzzedDataProvider* provider) {
  for (const auto& [dir, file] : kFiles) {
    CHECK(WriteFileAndCreateParentDirs(root_dir.Append(dir).Append(file),
                                       provider->ConsumeRandomLengthString()));
  }
}

void OnGetSystemInfoResponse(
    ash::cros_healthd::mojom::SystemResultPtr* response_update,
    ash::cros_healthd::mojom::SystemResultPtr response) {
  *response_update = std::move(response);
}

}  // namespace

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOGGING_FATAL);  // Disable logging.
    // Needed for TestTimeouts::Initialize().
    base::CommandLine::Init(0, nullptr);
    // Needed for SingleThreadTaskEnvironment.
    // TestTimeouts::Initialize() should be called exactly once.
    TestTimeouts::Initialize();
  }

  // base::RunLoop requires a task environment.
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  // 100 KiB max input size. Doing multiple writes and read for significantly
  // large files can potentially cause the fuzzer to timeout.
  constexpr int kMaxInputSize = 102400;
  if (size > kMaxInputSize)
    return 0;

  FuzzedDataProvider provider(data, size);
  // Populate the fake lsb-release file.
  base::test::ScopedChromeOSVersionInfo version(
      provider.ConsumeRandomLengthString(), base::Time::Now());

  MockContext mock_context;

  SetUpSystemFiles(mock_context.root_dir(), &provider);
  mock_context.fake_system_config()->SetHasSkuNumber(true);
  mock_context.fake_system_config()->SetMarketingName("fake_marketing_name");
  mock_context.fake_system_config()->SetOemName("fake_oem_name");
  mock_context.fake_system_config()->SetCodeName("fake_code_name");

  base::RunLoop run_loop;
  ash::cros_healthd::mojom::SystemResultPtr result;
  FetchSystemInfo(&mock_context,
                  base::BindOnce(&OnGetSystemInfoResponse, &result));
  run_loop.RunUntilIdle();

  return 0;
}

}  // namespace diagnostics
