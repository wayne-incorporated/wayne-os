// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/fs.h>
#include <linux/limits.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#include <cstdint>
#include <string>

#include <base/logging.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/strings/stringprintf.h>
#include <base/types/expected.h>
#include <base/posix/eintr_wrapper.h>
#include <rootdev/rootdev.h>

#include "diagnostics/cros_healthd/fetchers/storage/platform.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kDevPrefix[] = "/dev/";

}

std::string Platform::GetRootDeviceName() const {
  char dev_path_cstr[PATH_MAX];

  // Get physical root device without partition
  int ret = rootdev(dev_path_cstr, sizeof(dev_path_cstr),
                    true /* resolve to physical */, true /* strip partition */);
  if (ret != 0) {
    PLOG(ERROR) << "Failed to retrieve root device";
    return "";
  }

  std::string dev_path = dev_path_cstr;

  if (dev_path.find(kDevPrefix) != 0) {
    PLOG(ERROR) << "Unexpected root device format " << dev_path;
    return "";
  }

  return dev_path.substr(std::string(kDevPrefix).length());
}

base::expected<uint64_t, mojom::ProbeErrorPtr> Platform::GetDeviceSizeBytes(
    const base::FilePath& dev_path) const {
  base::ScopedFD fd(HANDLE_EINTR(
      open(dev_path.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (!fd.is_valid()) {
    return base::unexpected(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        base::StringPrintf("Failed to open %s", dev_path.value().c_str())));
  }

  uint64_t size;
  auto ret = ioctl(fd.get(), BLKGETSIZE64, &size);
  if (ret != 0) {
    return base::unexpected(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        base::StringPrintf("Failed to query size of %s : %d",
                           dev_path.value().c_str(), ret)));
  }
  return size;
}

base::expected<uint64_t, mojom::ProbeErrorPtr>
Platform::GetDeviceBlockSizeBytes(const base::FilePath& dev_path) const {
  base::ScopedFD fd(HANDLE_EINTR(
      open(dev_path.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (!fd.is_valid()) {
    return base::unexpected(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        base::StringPrintf("Failed to open %s", dev_path.value().c_str())));
  }

  int blksize;
  auto ret = ioctl(fd.get(), BLKSSZGET, &blksize);
  if (ret != 0) {
    return base::unexpected(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        base::StringPrintf("Failed to query block size of %s : %d",
                           dev_path.value().c_str(), ret)));
  }
  if (blksize <= 0) {
    return base::unexpected(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        base::StringPrintf("Ioctl returned invalid blocksize for %s: %d",
                           dev_path.value().c_str(), blksize)));
  }
  return static_cast<uint64_t>(blksize);
}

}  // namespace diagnostics
