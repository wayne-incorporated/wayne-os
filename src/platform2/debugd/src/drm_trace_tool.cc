// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This tool is used for getting dmesg information through debugd.

#include "debugd/src/drm_trace_tool.h"

#include <optional>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_util.h>
#include <brillo/files/safe_fd.h>
#include <debugd/src/error_utils.h>

namespace debugd {

namespace {
// Categories copied from drm_debug_category:
// https://elixir.bootlin.com/linux/v5.14.12/source/include/drm/drm_print.h#L277
// These are not exposed in libdrm or other userspace headers, so we need to
// duplicate them here.
enum DRMDebugCategories {
  DRM_UT_CORE = 0x01,
  DRM_UT_DRIVER = 0x02,
  DRM_UT_KMS = 0x04,
  DRM_UT_PRIME = 0x08,
  DRM_UT_ATOMIC = 0x10,
  DRM_UT_VBL = 0x20,
  DRM_UT_STATE = 0x40,
  DRM_UT_LEASE = 0x80,
  DRM_UT_DP = 0x100,
  DRM_UT_DRMRES = 0x200,
};

constexpr bool AreEqual(DRMDebugCategories c1, DRMTraceCategories c2) {
  typedef std::underlying_type<DRMDebugCategories>::type t1;
  typedef std::underlying_type<DRMTraceCategories>::type t2;
  return static_cast<t1>(c1) == static_cast<t2>(c2);
}

static_assert(AreEqual(DRM_UT_CORE, DRMTraceCategory_CORE));
static_assert(AreEqual(DRM_UT_DRIVER, DRMTraceCategory_DRIVER));
static_assert(AreEqual(DRM_UT_KMS, DRMTraceCategory_KMS));
static_assert(AreEqual(DRM_UT_PRIME, DRMTraceCategory_PRIME));
static_assert(AreEqual(DRM_UT_ATOMIC, DRMTraceCategory_ATOMIC));
static_assert(AreEqual(DRM_UT_VBL, DRMTraceCategory_VBL));
static_assert(AreEqual(DRM_UT_STATE, DRMTraceCategory_STATE));
static_assert(AreEqual(DRM_UT_LEASE, DRMTraceCategory_LEASE));
static_assert(AreEqual(DRM_UT_DP, DRMTraceCategory_DP));
static_assert(AreEqual(DRM_UT_DRMRES, DRMTraceCategory_DRMRES));

constexpr uint32_t kDefaultMask = DRM_UT_DRIVER | DRM_UT_KMS | DRM_UT_DP;
constexpr uint32_t kAllCategories = 0x3FF;
constexpr uint32_t kDefaultTraceBufferSizeKb = 64;
// 2MB * num_cpus. This is somewhat arbitrary. Increase in size if we need more.
constexpr uint32_t kDebugTraceBufferSizeKb = 2 * 1024;
// 256K, to account for large blocks of text such as modetest output.
constexpr uint32_t kMaxLogSize = 256 * 1024;

// Drop the first slash since the root path can be set for testing.
constexpr char kTraceMaskFile[] = "sys/module/drm/parameters/trace";
constexpr char kTraceBufferSizeFile[] =
    "sys/kernel/tracing/instances/drm/buffer_size_kb";
constexpr char kTraceMarkerFile[] =
    "sys/kernel/tracing/instances/drm/trace_marker";
constexpr char kSnapshotDirPath[] = "var/log/display_debug";
constexpr char kDrmTraceLogName[] = "drm_trace_verbose";
constexpr char kModetestLogName[] = "modetest";

constexpr char kDRMTraceToolErrorString[] =
    "org.chromium.debugd.error.DRMTrace";

// Convert |size| to the corresponding DRMTraceSizes enum value. Returns
// false if |size| is not a valid enum value.
bool ConvertSize(uint32_t size, DRMTraceSizes* out_size) {
  if (size == DRMTraceSize_DEFAULT)
    *out_size = DRMTraceSize_DEFAULT;
  else if (size == DRMTraceSize_DEBUG)
    *out_size = DRMTraceSize_DEBUG;
  else
    return false;

  return true;
}

// Convert |type| to the corresponding DRMSnapshotType enum value. Returns
// false if |type| is not a valid enum value.
bool ConvertType(uint32_t type, DRMSnapshotType* out_type) {
  switch (type) {
    case DRMSnapshotType_TRACE:
      *out_type = DRMSnapshotType_TRACE;
      return true;
    case DRMSnapshotType_MODETEST:
      *out_type = DRMSnapshotType_MODETEST;
      return true;
    default:
      return false;
  }
}

base::FilePath GenerateSnapshotFilePath(const char* base_name) {
  base::Time now = base::Time::Now();
  base::Time::Exploded exploded;
  now.LocalExplode(&exploded);

  // var/log/blah/trace.YYYYMMDD-HHMMSS
  return base::FilePath(kSnapshotDirPath)
      .Append(base::FilePath(base::StringPrintf(
          "%s.%04d%02d%02d-%02d%02d%02d", base_name, exploded.year,
          exploded.month, exploded.day_of_month, exploded.hour, exploded.minute,
          exploded.second)));
}

}  // namespace

DRMTraceTool::DRMTraceTool(LogProvider* log_provider)
    : DRMTraceTool(base::FilePath("/"), log_provider) {}

DRMTraceTool::DRMTraceTool(const base::FilePath& root_path,
                           LogProvider* log_provider)
    : root_path_(root_path), log_provider_(log_provider) {
  // Ensure that the DRM trace parameters are initialized to default when debugd
  // starts.
  SetToDefault();
}

bool DRMTraceTool::SetCategories(brillo::ErrorPtr* error, uint32_t categories) {
  base::FilePath mask_path = root_path_.Append(kTraceMaskFile);

  if (categories & ~kAllCategories) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Unknown category flags: 0x%x",
                         categories & ~kAllCategories);
    return false;
  }

  // Flags for categories match the flags expected by the kernel for drm_trace,
  // as asserted above.
  uint32_t mask = categories;
  if (categories == 0)
    mask = kDefaultMask;

  return WriteToFile(error, mask_path, base::StringPrintf("%d", mask));
}

bool DRMTraceTool::SetSize(brillo::ErrorPtr* error, uint32_t size_enum) {
  base::FilePath size_path = root_path_.Append(kTraceBufferSizeFile);

  DRMTraceSizes drm_trace_size;
  if (!ConvertSize(size_enum, &drm_trace_size)) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Invalid value for size: %u", size_enum);
    return false;
  }

  uint32_t size_kb = kDefaultTraceBufferSizeKb;
  if (drm_trace_size == DRMTraceSize_DEBUG)
    size_kb = kDebugTraceBufferSizeKb;

  return WriteToFile(error, size_path, base::StringPrintf("%d", size_kb));
}

bool DRMTraceTool::AnnotateLog(brillo::ErrorPtr* error,
                               const std::string& log) {
  base::FilePath marker_path = root_path_.Append(kTraceMarkerFile);

  // Ensure the string is a reasonable size.
  if (log.size() >= kMaxLogSize) {
    DEBUGD_ADD_ERROR(error, kDRMTraceToolErrorString, "Log too large.");
    return false;
  }

  // Sanitize the log. Allow only ascii printable characters and whitespace
  // (which will include newlines). Invalid characters will be replaced
  // with '_'.
  const char kReplacementChar = '_';
  std::string sanitized_log;
  sanitized_log.resize(log.size());
  std::replace_copy_if(
      log.begin(), log.end(), sanitized_log.begin(),
      [](auto c) {
        return !(base::IsAsciiPrintable(c) || base::IsAsciiWhitespace(c));
      },
      kReplacementChar);

  return WriteToFile(error, marker_path, sanitized_log);
}

bool DRMTraceTool::Snapshot(brillo::ErrorPtr* error, uint32_t type_enum) {
  DRMSnapshotType drm_snapshot_type;
  if (!ConvertType(type_enum, &drm_snapshot_type)) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Invalid value for type: %u", type_enum);
    return false;
  }

  std::string log_name;
  switch (drm_snapshot_type) {
    case DRMSnapshotType_TRACE:
      log_name = kDrmTraceLogName;
      break;
    case DRMSnapshotType_MODETEST: {
      log_name = kModetestLogName;
      break;
    }
  }

  std::optional<std::string> log_contents = log_provider_->GetLog(log_name);
  if (!log_contents.has_value()) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Failed to get named log: : %s", log_name.c_str());
    return false;
  }
  const base::FilePath snapshot_path =
      root_path_.Append(GenerateSnapshotFilePath(log_name.c_str()));

  // Create the empty snapshot file to copy the log contents into.
  brillo::SafeFD::SafeFDResult result = brillo::SafeFD::Root();
  if (!brillo::SafeFD::IsError(result.second))
    result = result.first.MakeFile(snapshot_path);
  if (brillo::SafeFD::IsError(result.second)) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Failed to create snapshot file: : %s",
                         snapshot_path.value().c_str());
    return false;
  }

  return WriteToFile(error, snapshot_path, log_contents.value());
}

bool DRMTraceTool::WriteToFile(brillo::ErrorPtr* error,
                               const base::FilePath& path,
                               const std::string& contents) {
  brillo::SafeFD::SafeFDResult result = brillo::SafeFD::Root();
  if (brillo::SafeFD::IsError(result.second)) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Failed to open SafeFD::Root(), error: %d",
                         result.second);
    return false;
  }

  result = result.first.OpenExistingFile(path);
  if (brillo::SafeFD::IsError(result.second)) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Failed to open %s, error: %d", path.value().c_str(),
                         result.second);
    return false;
  }

  // SafeFD::Replace is not used here because
  // /sys/kernel/tracing/instances/drm/trace_marker does not support seek
  // (b/227339558).
  brillo::SafeFD::Error safefd_error =
      result.first.Write(contents.c_str(), contents.size());
  if (brillo::SafeFD::IsError(safefd_error)) {
    DEBUGD_ADD_ERROR_FMT(error, kDRMTraceToolErrorString,
                         "Failed to write to %s, error: %d",
                         path.value().c_str(), safefd_error);
    return false;
  }

  return true;
}

void DRMTraceTool::OnSessionStarted() {
  SetToDefault();
}

void DRMTraceTool::OnSessionStopped() {
  SetToDefault();
}

void DRMTraceTool::SetToDefault() {
  brillo::ErrorPtr error;
  if (!SetCategories(&error, 0))
    LOG(WARNING) << "Failed to reset categories; drm_trace may have unexpected "
                    "log entries.";
  if (!SetSize(&error, DRMTraceSize_DEFAULT))
    LOG(WARNING) << "Failed to reset trace buffer size; drm_trace may be "
                    "larger than expected.";
}

}  // namespace debugd
