// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/internal_backlight.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/task/single_thread_task_executor.h>
#include "fuzzer/FuzzedDataProvider.h"

#include "power_manager/common/clock.h"
#include "power_manager/common/util.h"

namespace {

// Create files to make the given directory look like it is a sysfs backlight
// dir. Copied as is form internal_backlight_test.cc
void PopulateBacklightDir(const base::FilePath& path,
                          int64_t brightness,
                          int64_t max_brightness) {
  CHECK(base::CreateDirectory(path));
  CHECK(power_manager::util::WriteInt64File(
      path.Append(
          power_manager::system::InternalBacklight::kBrightnessFilename),
      brightness));
  CHECK(power_manager::util::WriteInt64File(
      path.Append(
          power_manager::system::InternalBacklight::kMaxBrightnessFilename),
      max_brightness));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Create a tempdir, which can help with cleanup at the end.
  base::ScopedTempDir temp_dir;
  CHECK(temp_dir.CreateUniqueTempDir());
  auto temp_dir_path = temp_dir.GetPath();
  FuzzedDataProvider data_provider(data, size);
  // Add a TaskExecutor to keep the fuzzer from crashing.
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  // Create a random name backlight, and run the Init() code through it.
  const base::FilePath random_test_dir = temp_dir_path.Append("random_test");

  // If the random name backlight can be interpreted as an absolute path,
  // base::FilePath::Append() crashes (since it doesn't expect this). So check
  // for that and return early if so.
  auto random_backlight_dirname =
      base::FilePath(data_provider.ConsumeRandomLengthString(100));
  if (random_backlight_dirname.IsAbsolute())
    return 0;

  const base::FilePath random_backlight_path =
      random_test_dir.Append(random_backlight_dirname);
  PopulateBacklightDir(random_backlight_path,
                       data_provider.ConsumeIntegral<int64_t>(),
                       data_provider.ConsumeIntegral<int64_t>());
  power_manager::system::InternalBacklight random_backlight;
  random_backlight.Init(random_test_dir, "*");

  // Now, we create a legitimate backlight. But set the following randomly:
  // - Max brightness
  // - Current brightness
  // - Target brightness
  // - Timeout duration.
  const base::FilePath real_test_dir = temp_dir_path.Append("real_test");
  const base::FilePath real_backlight_path = real_test_dir.Append("backlight");
  PopulateBacklightDir(real_backlight_path,
                       data_provider.ConsumeIntegral<int64_t>(),
                       data_provider.ConsumeIntegral<int64_t>());
  power_manager::system::InternalBacklight real_backlight;
  const base::TimeTicks start_time =
      base::TimeTicks() + base::Microseconds(10000);
  real_backlight.clock()->set_current_time_for_testing(start_time);

  // Try creating a backlight, but if the Init() fails, just return.
  bool created = real_backlight.Init(real_test_dir, "*");
  if (!created)
    return 0;

  int64_t target_brightness = data_provider.ConsumeIntegral<int64_t>();
  const base::TimeDelta duration =
      base::Milliseconds(data_provider.ConsumeIntegral<uint32_t>());
  const base::TimeTicks end_time = start_time + duration;
  real_backlight.SetBrightnessLevel(target_brightness, duration);

  real_backlight.clock()->set_current_time_for_testing(end_time);

  return 0;
}
