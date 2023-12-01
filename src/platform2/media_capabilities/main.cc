// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include "media_capabilities/camera.h"
#include "media_capabilities/common.h"

#if defined(USE_V4L2_CODEC)
#include "media_capabilities/v4l2.h"
#endif  // defined(USE_V4L2_CODEC)

#if defined(USE_VAAPI)
#include "media_capabilities/vaapi.h"
#endif  // defined(USE_VAAPI)

int main(int argc, char* argv[]) {
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");
  brillo::FlagHelper::Init(
      argc, argv, "Command line tool to detect video and camera capabilities");
  brillo::InitLog(brillo::kLogToStderrIfTty);
  logging::SetMinLogLevel(FLAGS_log_level);

  using DetectFunction = base::RepeatingCallback<std::vector<Capability>()>;
  const DetectFunction kDetectFunctions[] = {
#if defined(USE_V4L2_CODEC)
    base::BindRepeating(&DetectV4L2Capabilities),
#endif  // defined(USE_V4L2_CODEC)
#if defined(USE_VAAPI)
    base::BindRepeating(&DetectVaapiCapabilities),
#endif  // defined(USE_VAAPI)
    base::BindRepeating(&DetectCameraCapabilities),
  };

  std::vector<Capability> capabilities;
  for (const DetectFunction& detect_function : kDetectFunctions) {
    for (const auto& cap : detect_function.Run())
      capabilities.push_back(cap);
  }

  // Remove duplicated capabilities to not print the same capability multiple
  // times when the same capabilities are available in V4L2 API and VA-API.
  std::sort(capabilities.begin(), capabilities.end());
  auto last = std::unique(capabilities.begin(), capabilities.end());
  capabilities.erase(last, capabilities.end());
  for (const auto& cap : capabilities)
    std::cout << cap.ToString() << std::endl;
}
