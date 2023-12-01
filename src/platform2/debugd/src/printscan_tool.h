// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PRINTSCAN_TOOL_H_
#define DEBUGD_SRC_PRINTSCAN_TOOL_H_

// This tool is used to create debug flag files for printing and scanning
// services that will put those services into debug modes.

#include "debugd/src/upstart_tools.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/debugd/dbus-constants.h>
#include <dbus/bus.h>

namespace debugd {

enum PrintscanFilePaths {
  PRINTSCAN_CUPS_FILEPATH,
  PRINTSCAN_IPPUSB_FILEPATH,
  PRINTSCAN_LORGNETTE_FILEPATH,
};

enum class PrintscanCategories {
  PRINTSCAN_NO_CATEGORIES = 0x0,
  PRINTSCAN_PRINTING_CATEGORY = 0x1,
  PRINTSCAN_SCANNING_CATEGORY = 0x2,
  PRINTSCAN_ALL_CATEGORIES = 0x3,
};

class PrintscanTool {
 public:
  explicit PrintscanTool(const scoped_refptr<dbus::Bus>& bus);
  PrintscanTool(const PrintscanTool&) = delete;
  PrintscanTool& operator=(const PrintscanTool&) = delete;
  ~PrintscanTool() = default;

  // Set categories to debug.
  bool DebugSetCategories(brillo::ErrorPtr* error,
                          PrintscanCategories categories);

  // Create a testing PrintscanTool with a given root path.
  static std::unique_ptr<PrintscanTool> CreateForTesting(
      const scoped_refptr<dbus::Bus>& bus,
      const base::FilePath& path,
      std::unique_ptr<UpstartTools> upstart_tools);

 private:
  // Creates an empty file at the given path from root_path_.
  bool CreateEmptyFile(PrintscanFilePaths path);

  // Deletes a file at the given path from root_path_.
  bool DeleteFile(PrintscanFilePaths path);

  // Creates or deletes Cups debug flag files.
  bool ToggleCups(brillo::ErrorPtr* error, bool enable);
  //
  // Creates or deletes Ippusb debug flag files.
  bool ToggleIppusb(brillo::ErrorPtr* error, bool enable);

  // Creates or deletes Lorgnette debug flag files.
  bool ToggleLorgnette(brillo::ErrorPtr* error, bool enable);

  // Restarts cupsd and lorgnette.
  bool RestartServices(brillo::ErrorPtr* error);

  // For testing only.
  PrintscanTool(const scoped_refptr<dbus::Bus>& bus,
                const base::FilePath& root_path,
                std::unique_ptr<UpstartTools> upstart_tools);

  scoped_refptr<dbus::Bus> bus_;
  const base::FilePath root_path_;
  std::unique_ptr<UpstartTools> upstart_tools_ =
      std::make_unique<UpstartToolsImpl>(bus_);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PRINTSCAN_TOOL_H_
