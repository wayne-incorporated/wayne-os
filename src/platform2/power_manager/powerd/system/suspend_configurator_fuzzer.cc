// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/suspend_configurator.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <featured/fake_platform_features.h>
#include "fuzzer/FuzzedDataProvider.h"

#include "power_manager/common/fake_prefs.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"

namespace {
constexpr char kSuspendModePath[] = "/sys/power/mem_sleep";

// Creates an empty sysfs file rooted in |temp_root_dir|. For example if
// |temp_root_dir| is "/tmp/xxx" and |sys_path| is "/sys/power/temp", creates
// "/tmp/xxx/sys/power/temp" with all necessary root directories.
// Copied from suspend_configurator_test.cc
void CreateSysfsFileInTempRootDir(const base::FilePath& temp_root_dir,
                                  const std::string& sys_path) {
  CHECK(!sys_path.empty());
  CHECK(base::StartsWith(sys_path, "/"));
  base::FilePath path = temp_root_dir.Append(sys_path.substr(1));
  CHECK(base::CreateDirectory(path.DirName()));
  CHECK_EQ(base::WriteFile(path, "", 0), 0);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider data_provider(data, size);
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  // Create fake directory structure.
  base::ScopedTempDir temp_root_dir;
  CHECK(temp_root_dir.CreateUniqueTempDir());
  base::FilePath temp_root_dir_path = temp_root_dir.GetPath();
  CreateSysfsFileInTempRootDir(
      temp_root_dir_path,
      power_manager::system::SuspendConfigurator::kConsoleSuspendPath.value());
  CreateSysfsFileInTempRootDir(temp_root_dir_path, kSuspendModePath);

  power_manager::system::SuspendConfigurator suspend_configurator;
  suspend_configurator.set_prefix_path_for_testing(temp_root_dir_path);

  // Fill in garbage prefs.
  power_manager::FakePrefs prefs;
  prefs.SetInt64(power_manager::kSuspendToIdlePref,
                 data_provider.ConsumeBool());
  prefs.SetInt64(power_manager::kEnableConsoleDuringSuspendPref,
                 data_provider.ConsumeBool());
  prefs.SetString(power_manager::kSuspendModePref,
                  data_provider.ConsumeRandomLengthString(20));

  auto dbus_wrapper = new power_manager::system::DBusWrapperStub();
  std::unique_ptr<feature::FakePlatformFeatures> platform_features =
      std::make_unique<feature::FakePlatformFeatures>(dbus_wrapper->GetBus());

  suspend_configurator.Init(platform_features.get(), &prefs);
  suspend_configurator.PrepareForSuspend(base::TimeDelta());

  return 0;
}
