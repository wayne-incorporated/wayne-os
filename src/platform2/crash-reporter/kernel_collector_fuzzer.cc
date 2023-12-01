// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>
#include <cinttypes>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <session_manager/dbus-proxy-mocks.h>

#include "crash-reporter/kernel_collector.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

namespace {

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

class KernelCollectorForFuzzing : public KernelCollector {
 public:
  KernelCollectorForFuzzing() : KernelCollector() {}

  void SetUpDBus() override {
    // Mock out all DBus calls so (a) we don't actually call DBus and (b) we
    // don't CHECK fail when the DBus calls fail.
    auto mock =
        std::make_unique<org::chromium::SessionManagerInterfaceProxyMock>();
    test_util::SetActiveSessions(mock.get(), {});
    session_manager_proxy_ = std::move(mock);
  }

  int Fuzz(FuzzedDataProvider* const data_provider) {
    // Put all files into a per-run temp directory.
    base::ScopedTempDir temp_dir;
    CHECK(temp_dir.CreateUniqueTempDir());
    base::FilePath test_dir = temp_dir.GetPath();
    paths::SetPrefixForTesting(test_dir);

    auto kcrash_dir = test_dir.Append("kcrash");
    CHECK(base::CreateDirectory(kcrash_dir));

    auto crash_directory = test_dir.Append("crash_directory");
    CHECK(base::CreateDirectory(crash_directory));

    auto arch = data_provider->ConsumeEnum<kernel_util::ArchKind>();

    auto eventlog = test_dir.Append("eventlog.txt");
    if (!WriteFuzzedFile(data_provider, eventlog))
      return 0;

    auto bios_log = test_dir.Append("bios_log");
    if (!WriteFuzzedFile(data_provider, bios_log))
      return 0;

    // Fuzz either a ramoops crash or EFI crash.
    if (data_provider->ConsumeBool()) {
      base::FilePath ramoops;

      if (data_provider->ConsumeBool()) {
        ramoops = kcrash_dir.Append("console-ramoops-0");
      } else if (data_provider->ConsumeBool()) {
        ramoops = kcrash_dir.Append("console-ramoops");
      } else {
        ramoops = kcrash_dir.Append("dmesg-ramoops-0");
      }
      if (!WriteFuzzedFile(data_provider, ramoops))
        return 0;
    } else {
      int maxEfiParts = data_provider->ConsumeIntegralInRange<int>(
          0, KernelCollector::EfiCrash::kMaxPart);
      uint64_t id = data_provider->ConsumeIntegral<uint64_t>();

      for (int i = 0; i < maxEfiParts; i++) {
        auto efikcrash = kcrash_dir.Append(base::StringPrintf(
            "dmesg-efi-%" PRIu64,
            (id * maxEfiParts + i) * KernelCollector::EfiCrash::kMaxDumpRecord +
                1));
        if (!WriteFuzzedFile(data_provider, efikcrash))
          return 0;
      }
    }

    Initialize(false);
    set_arch(arch);

    OverrideEventLogPath(eventlog);
    OverrideBiosLogPath(bios_log);
    OverridePreservedDumpPath(kcrash_dir);

    Collect(/*use_saved_lsb=*/false);

    return 0;
  }

 private:
  bool WriteFuzzedFile(FuzzedDataProvider* const data_provider,
                       const base::FilePath& file_path) {
    constexpr int kArbitraryMaxFileLength = 1024 * 1024;

    auto path = base::FilePath(file_path);
    base::File file(path,
                    base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    if (!file.created()) {
      LOG(ERROR) << "Failed to create " << file_path.value();
      return false;
    }

    const std::string& file_contents =
        data_provider->ConsumeRandomLengthString(kArbitraryMaxFileLength);
    file.Write(0, file_contents.c_str(), file_contents.length());

    return true;
  }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  FuzzedDataProvider data_provider(data, size);
  KernelCollectorForFuzzing collector;

  return collector.Fuzz(&data_provider);
}
