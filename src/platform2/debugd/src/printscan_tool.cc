// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/printscan_tool.h"

#include <sys/mount.h>

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/errors/error.h>
#include <brillo/files/file_util.h>
#include <chromeos/dbus/debugd/dbus-constants.h>
#include <debugd/src/error_utils.h>
#include <debugd/src/process_with_output.h>

namespace debugd {

namespace {

constexpr uint32_t kAllCategories =
    PrintscanDebugCategory_PRINTING | PrintscanDebugCategory_SCANNING;

constexpr char kPrintscanToolErrorString[] =
    "org.chromium.debugd.error.Printscan";

const base::FilePath kCupsFilePath =
    base::FilePath("run/cups/debug/debug-flag");
const base::FilePath kIppusbFilePath =
    base::FilePath("run/ippusb/debug/debug-flag");
const base::FilePath kLorgnetteFilePath =
    base::FilePath("run/lorgnette/debug/debug-flag");

}  // namespace

PrintscanTool::PrintscanTool(const scoped_refptr<dbus::Bus>& bus)
    : PrintscanTool(
          bus, base::FilePath("/"), std::make_unique<UpstartToolsImpl>(bus)) {}

PrintscanTool::PrintscanTool(const scoped_refptr<dbus::Bus>& bus,
                             const base::FilePath& root_path,
                             std::unique_ptr<UpstartTools> upstart_tools)
    : bus_(bus),
      root_path_(root_path),
      upstart_tools_(std::move(upstart_tools)) {}

bool PrintscanTool::DebugSetCategories(brillo::ErrorPtr* error,
                                       PrintscanCategories categories) {
  if (static_cast<uint32_t>(categories) & ~kAllCategories) {
    DEBUGD_ADD_ERROR_FMT(error, kPrintscanToolErrorString,
                         "Unknown category flags: 0x%x",
                         static_cast<uint32_t>(categories) & ~kAllCategories);
    return false;
  }

  bool success = true;
  // Enable Cups logging if the printing category is enabled.
  success = ToggleCups(error, static_cast<uint32_t>(categories) &
                                  PrintscanDebugCategory_PRINTING);
  if (success) {
    // Enable Ippusb logging if the printing or scanning category is
    // enabled.
    success = ToggleIppusb(error, static_cast<uint32_t>(categories) &
                                      (PrintscanDebugCategory_SCANNING |
                                       PrintscanDebugCategory_PRINTING));
  }
  if (success) {
    // Enable Lorgnette logging is the scanning category is enabled.
    ToggleLorgnette(error, static_cast<uint32_t>(categories) &
                               PrintscanDebugCategory_SCANNING);
  }
  if (!success) {
    // Disable all logging if there were any errors setting up logging.
    ToggleCups(error, false);
    ToggleIppusb(error, false);
    ToggleLorgnette(error, false);
  }
  success = RestartServices(error);

  return success;
}

std::unique_ptr<PrintscanTool> PrintscanTool::CreateForTesting(
    const scoped_refptr<dbus::Bus>& bus,
    const base::FilePath& path,
    std::unique_ptr<UpstartTools> upstart_tools) {
  return std::unique_ptr<PrintscanTool>(
      new PrintscanTool(bus, path, std::move(upstart_tools)));
}

// Create an empty file at the given path from root_path_.
bool PrintscanTool::CreateEmptyFile(PrintscanFilePaths path) {
  base::FilePath full_path;
  switch (path) {
    case PRINTSCAN_CUPS_FILEPATH:
      full_path = root_path_.Append(kCupsFilePath);
      break;
    case PRINTSCAN_IPPUSB_FILEPATH:
      full_path = root_path_.Append(kIppusbFilePath);
      break;
    case PRINTSCAN_LORGNETTE_FILEPATH:
      full_path = root_path_.Append(kLorgnetteFilePath);
      break;
  }
  return base::WriteFile(full_path, "", 0) == 0;
}

// Delete a file at the given path from root_path_.
bool PrintscanTool::DeleteFile(PrintscanFilePaths path) {
  base::FilePath full_path;
  switch (path) {
    case PRINTSCAN_CUPS_FILEPATH:
      full_path = root_path_.Append(kCupsFilePath);
      break;
    case PRINTSCAN_IPPUSB_FILEPATH:
      full_path = root_path_.Append(kIppusbFilePath);
      break;
    case PRINTSCAN_LORGNETTE_FILEPATH:
      full_path = root_path_.Append(kLorgnetteFilePath);
      break;
  }
  return brillo::DeleteFile(full_path);
}

// Enable Cups debug logs if `enable` is set, otherwise disable the logs.
// Return true on success.
bool PrintscanTool::ToggleCups(brillo::ErrorPtr* error, bool enable) {
  if (enable) {
    if (!CreateEmptyFile(PRINTSCAN_CUPS_FILEPATH)) {
      DEBUGD_ADD_ERROR(error, kPrintscanToolErrorString,
                       "Failed to create cups debug-flag.");
      return false;
    }
  } else {
    if (!DeleteFile(PRINTSCAN_CUPS_FILEPATH)) {
      DEBUGD_ADD_ERROR(error, kPrintscanToolErrorString,
                       "Failed to delete cups debug-flag.");
      return false;
    }
  }
  return true;
}

// Enable Ippusb debug logs if `enable` is set, otherwise disable the logs.
// Return true on success.
bool PrintscanTool::ToggleIppusb(brillo::ErrorPtr* error, bool enable) {
  if (enable) {
    if (!CreateEmptyFile(PRINTSCAN_IPPUSB_FILEPATH)) {
      DEBUGD_ADD_ERROR(error, kPrintscanToolErrorString,
                       "Failed to create ippusb debug-flag.");
      return false;
    }
  } else {
    if (!DeleteFile(PRINTSCAN_IPPUSB_FILEPATH)) {
      DEBUGD_ADD_ERROR(error, kPrintscanToolErrorString,
                       "Failed to delete ippusb delete-flag.");
      return false;
    }
  }
  return true;
}

// Enable Lorgnette debug logs if `enable` is set, otherwise disable the logs.
// Return true on success.
bool PrintscanTool::ToggleLorgnette(brillo::ErrorPtr* error, bool enable) {
  if (enable) {
    if (!CreateEmptyFile(PRINTSCAN_LORGNETTE_FILEPATH)) {
      DEBUGD_ADD_ERROR(error, kPrintscanToolErrorString,
                       "Failed to create lorgnette debug-flag.");
      return false;
    }
  } else {
    if (!DeleteFile(PRINTSCAN_LORGNETTE_FILEPATH)) {
      DEBUGD_ADD_ERROR(error, kPrintscanToolErrorString,
                       "Failed to delete lorgnette debug-flag.");
      return false;
    }
  }
  return true;
}

// Restart cups, lorgnette, and ippusb_bridge.
bool PrintscanTool::RestartServices(brillo::ErrorPtr* error) {
  // cupsd is intended to have the same lifetime as the ui, so we need to
  // fully restart it.
  bool success = upstart_tools_->RestartJob("cupsd", error);

  // lorgnette will be restarted when the next d-bus call happens, so it
  // can simply be shut down.
  success &= upstart_tools_->StopJob("lorgnette", error);
  return success;
}

}  // namespace debugd
