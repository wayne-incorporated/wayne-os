// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "printscanmgr/daemon/printscan_tool.h"

#include <set>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>
#include <printscanmgr/proto_bindings/printscanmgr_service.pb.h>

namespace printscanmgr {

namespace {

const base::FilePath kCupsFilePath =
    base::FilePath("run/cups/debug/debug-flag");
const base::FilePath kIppusbFilePath =
    base::FilePath("run/ippusb/debug/debug-flag");
const base::FilePath kLorgnetteFilePath =
    base::FilePath("run/lorgnette/debug/debug-flag");

}  // namespace

PrintscanTool::PrintscanTool(mojo::PendingRemote<mojom::Executor> remote)
    : PrintscanTool(std::move(remote), base::FilePath("/")) {}

PrintscanTool::PrintscanTool(mojo::PendingRemote<mojom::Executor> remote,
                             const base::FilePath& root_path)
    : root_path_(root_path) {
  remote_.Bind(std::move(remote));
}

PrintscanDebugSetCategoriesResponse PrintscanTool::DebugSetCategories(
    const PrintscanDebugSetCategoriesRequest& request) {
  PrintscanDebugSetCategoriesResponse response;

  std::set<PrintscanDebugSetCategoriesRequest::DebugLogCategory> categories;
  for (const auto category : request.categories()) {
    if (!PrintscanDebugSetCategoriesRequest_DebugLogCategory_IsValid(
            category)) {
      LOG(ERROR) << "Unknown category flag: " << category;
      response.set_result(false);
      return response;
    }
    categories.insert(
        static_cast<PrintscanDebugSetCategoriesRequest::DebugLogCategory>(
            category));
  }

  auto printing_search = categories.find(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_PRINTING);
  auto scanning_search = categories.find(
      PrintscanDebugSetCategoriesRequest::DEBUG_LOG_CATEGORY_SCANNING);
  bool enable_cups = printing_search != categories.end();
  bool enable_ippusb = printing_search != categories.end() ||
                       scanning_search != categories.end();
  bool enable_lorgnette = scanning_search != categories.end();

  bool success = true;
  // Enable Cups logging if the printing category is enabled.
  success = ToggleCups(enable_cups);
  if (success) {
    // Enable Ippusb logging if the printing or scanning category is
    // enabled.
    success = ToggleIppusb(enable_ippusb);
  }
  if (success) {
    // Enable Lorgnette logging if the scanning category is enabled.
    success = ToggleLorgnette(enable_lorgnette);
  }
  if (!success) {
    // Disable all logging if there were any errors setting up logging.
    ToggleCups(false);
    ToggleIppusb(false);
    ToggleLorgnette(false);
  }
  success &= RestartServices();

  response.set_result(success);
  return response;
}

// static
std::unique_ptr<PrintscanTool> PrintscanTool::CreateForTesting(
    mojo::PendingRemote<mojom::Executor> remote, const base::FilePath& path) {
  return std::unique_ptr<PrintscanTool>(
      new PrintscanTool(std::move(remote), path));
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
bool PrintscanTool::ToggleCups(bool enable) {
  if (enable) {
    if (!CreateEmptyFile(PRINTSCAN_CUPS_FILEPATH)) {
      LOG(ERROR) << "Failed to create cups debug-flag.";
      return false;
    }
    LOG(INFO) << "Advanced CUPS logging enabled.";
  } else {
    if (!DeleteFile(PRINTSCAN_CUPS_FILEPATH)) {
      LOG(ERROR) << "Failed to delete cups debug-flag.";
      return false;
    }
    LOG(INFO) << "Advanced CUPS logging disabled.";
  }
  return true;
}

// Enable Ippusb debug logs if `enable` is set, otherwise disable the logs.
// Return true on success.
bool PrintscanTool::ToggleIppusb(bool enable) {
  if (enable) {
    if (!CreateEmptyFile(PRINTSCAN_IPPUSB_FILEPATH)) {
      LOG(ERROR) << "Failed to create ippusb debug-flag.";
      return false;
    }
    LOG(INFO) << "Advanced ippusb logging enabled.";
  } else {
    if (!DeleteFile(PRINTSCAN_IPPUSB_FILEPATH)) {
      LOG(ERROR) << "Failed to delete ippusb delete-flag.";
      return false;
    }
    LOG(INFO) << "Advanced ippusb logging disabled.";
  }
  return true;
}

// Enable Lorgnette debug logs if `enable` is set, otherwise disable the logs.
// Return true on success.
bool PrintscanTool::ToggleLorgnette(bool enable) {
  if (enable) {
    if (!CreateEmptyFile(PRINTSCAN_LORGNETTE_FILEPATH)) {
      LOG(ERROR) << "Failed to create lorgnette debug-flag.";
      return false;
    }
    LOG(INFO) << "Advanced lorgnette logging enabled.";
  } else {
    if (!DeleteFile(PRINTSCAN_LORGNETTE_FILEPATH)) {
      LOG(ERROR) << "Failed to delete lorgnette debug-flag.";
      return false;
    }
    LOG(INFO) << "Advanced lorgnette logging disabled.";
  }
  return true;
}

// Restart cups and lorgnette.
bool PrintscanTool::RestartServices() {
  // cupsd is intended to have the same lifetime as the ui, so we need to
  // fully restart it.
  std::string error;
  bool cups_success;
  if (!remote_->RestartUpstartJob(mojom::UpstartJob::kCupsd, &cups_success,
                                  &error)) {
    LOG(ERROR)
        << "Error calling executor mojo method RestartUpstartJob for cupsd.";
  }
  if (!cups_success) {
    LOG(ERROR) << "Executor mojo method RestartUpstartJob for cupsd failed: "
               << error;
  }

  // lorgnette will be restarted when the next d-bus call happens, so it
  // can simply be shut down.
  bool lorgnette_success;
  if (!remote_->StopUpstartJob(mojom::UpstartJob::kLorgnette,
                               &lorgnette_success, &error)) {
    LOG(ERROR)
        << "Error calling executor mojo method StopUpstartJob for lorgnette.";
  }
  if (!lorgnette_success) {
    LOG(ERROR) << "Executor mojo method StopUpstartJob for lorgnette failed: "
               << error;
  }

  return cups_success && lorgnette_success;
}

}  // namespace printscanmgr
