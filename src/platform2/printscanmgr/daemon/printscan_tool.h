// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_DAEMON_PRINTSCAN_TOOL_H_
#define PRINTSCANMGR_DAEMON_PRINTSCAN_TOOL_H_

#include <memory>

#include <base/files/file_path.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <printscanmgr/proto_bindings/printscanmgr_service.pb.h>

#include "printscanmgr/mojom/executor.mojom.h"

namespace printscanmgr {

enum PrintscanFilePaths {
  PRINTSCAN_CUPS_FILEPATH,
  PRINTSCAN_IPPUSB_FILEPATH,
  PRINTSCAN_LORGNETTE_FILEPATH,
};

// This tool is used to create debug flag files for printing and scanning
// services that will put those services into debug modes.
class PrintscanTool {
 public:
  explicit PrintscanTool(mojo::PendingRemote<mojom::Executor> remote);
  PrintscanTool(const PrintscanTool&) = delete;
  PrintscanTool& operator=(const PrintscanTool&) = delete;
  ~PrintscanTool() = default;

  // Set categories to debug.
  PrintscanDebugSetCategoriesResponse DebugSetCategories(
      const PrintscanDebugSetCategoriesRequest& request);

  // Create a PrintscanTool with the given root path. Only for unit testing.
  static std::unique_ptr<PrintscanTool> CreateForTesting(
      mojo::PendingRemote<mojom::Executor> remote, const base::FilePath& path);

 private:
  // Creates an empty file at the given path from `root_path_`.
  bool CreateEmptyFile(PrintscanFilePaths path);

  // Deletes a file at the given path from `root_path_`.
  bool DeleteFile(PrintscanFilePaths path);

  // Creates or deletes Cups debug flag files.
  bool ToggleCups(bool enable);
  //
  // Creates or deletes Ippusb debug flag files.
  bool ToggleIppusb(bool enable);

  // Creates or deletes Lorgnette debug flag files.
  bool ToggleLorgnette(bool enable);

  // Restarts cupsd and lorgnette.
  bool RestartServices();

  // For testing only.
  PrintscanTool(mojo::PendingRemote<mojom::Executor> remote,
                const base::FilePath& root_path);

  const base::FilePath root_path_;
  mojo::Remote<mojom::Executor> remote_;
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_DAEMON_PRINTSCAN_TOOL_H_
