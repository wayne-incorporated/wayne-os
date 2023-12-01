// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_CLI_SCAN_HANDLER_H_
#define LORGNETTE_CLI_SCAN_HANDLER_H_

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

#include "lorgnette/cli/async_handler.h"
#include "lorgnette/dbus-proxies.h"

namespace lorgnette::cli {

// TODO(b/248023651): Add tests for this class when a fake Manager is available.
class ScanHandler : public AsyncHandler {
 public:
  using ManagerProxy = org::chromium::lorgnette::ManagerProxy;

  ScanHandler(base::RepeatingClosure quit_closure,
              ManagerProxy* manager,
              std::string scanner_name,
              std::string output_pattern);
  ScanHandler(const ScanHandler&) = delete;
  ScanHandler& operator=(const ScanHandler&) = delete;
  ~ScanHandler() override;
  void ConnectSignal() override;

  bool StartScan(uint32_t resolution,
                 const lorgnette::DocumentSource& scan_source,
                 const std::optional<lorgnette::ScanRegion>& scan_region,
                 lorgnette::ColorMode color_mode,
                 lorgnette::ImageFormat image_format);

 private:
  void HandleScanStatusChangedSignal(
      const lorgnette::ScanStatusChangedSignal& signal_serialized);

  void RequestNextPage();
  std::optional<lorgnette::GetNextImageResponse> GetNextImage(
      const base::FilePath& output_path);

  std::string scanner_name_;
  std::string output_pattern_;
  std::string format_extension_;
  std::optional<std::string> scan_uuid_;
  int current_page_;

  // Keep as the last member variable.
  base::WeakPtrFactory<ScanHandler> weak_factory_{this};
};

}  // namespace lorgnette::cli

#endif  // LORGNETTE_CLI_SCAN_HANDLER_H_
