// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/backlight_fetcher.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kRelativeBacklightDirectoryPath[] = "sys/class/backlight";

// Fetches backlight information for a specific sysfs path. On success,
// populates |output_info| with the fetched information and returns a
// std::nullopt. When an error occurs, a ProbeError is returned and
// |output_info| does not contain valid information.
std::optional<mojom::ProbeErrorPtr> FetchBacklightInfoForPath(
    const base::FilePath& path, mojom::BacklightInfoPtr* output_info) {
  DCHECK(output_info);

  mojom::BacklightInfo info;
  info.path = path.value();

  if (!ReadInteger(path, "max_brightness", &base::StringToUint,
                   &info.max_brightness)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError,
        "Failed to read max_brightness for " + path.value());
  }

  if (!ReadInteger(path, "brightness", &base::StringToUint, &info.brightness)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError,
        "Failed to read brightness for " + path.value());
  }

  *output_info = info.Clone();
  return std::nullopt;
}

}  // namespace

mojom::BacklightResultPtr BacklightFetcher::FetchBacklightInfo() {
  std::vector<mojom::BacklightInfoPtr> backlights;

  if (!context_->system_config()->HasBacklight())
    return mojom::BacklightResult::NewBacklightInfo(std::move(backlights));

  base::FileEnumerator backlight_dirs(
      context_->root_dir().AppendASCII(kRelativeBacklightDirectoryPath),
      false /* is_recursive */,
      base::FileEnumerator::SHOW_SYM_LINKS | base::FileEnumerator::FILES |
          base::FileEnumerator::DIRECTORIES);

  for (base::FilePath path = backlight_dirs.Next(); !path.empty();
       path = backlight_dirs.Next()) {
    VLOG(1) << "Processing the node " << path.value();
    mojom::BacklightInfoPtr backlight;
    auto error = FetchBacklightInfoForPath(path, &backlight);
    if (error.has_value()) {
      return mojom::BacklightResult::NewError(std::move(error.value()));
    }
    DCHECK_NE(backlight->path, "");
    DCHECK_LE(backlight->brightness, backlight->max_brightness);
    backlights.push_back(std::move(backlight));
  }

  if (backlights.empty()) {
    return mojom::BacklightResult::NewError(CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError,
        "Device supports backlight, but no backlight information found in " +
            context_->root_dir()
                .AppendASCII(kRelativeBacklightDirectoryPath)
                .value()));
  }

  return mojom::BacklightResult::NewBacklightInfo(std::move(backlights));
}

}  // namespace diagnostics
