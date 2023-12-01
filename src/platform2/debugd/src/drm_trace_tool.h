// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This tool is used for getting dmesg information through debugd.

#ifndef DEBUGD_SRC_DRM_TRACE_TOOL_H_
#define DEBUGD_SRC_DRM_TRACE_TOOL_H_

#include <string>

#include <base/files/file_path.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/debugd/dbus-constants.h>
#include <debugd/src/log_provider.h>
#include <debugd/src/session_manager_observer_interface.h>

namespace debugd {

class DRMTraceTool : public SessionManagerObserverInterface {
 public:
  explicit DRMTraceTool(LogProvider* provider);
  DRMTraceTool(const DRMTraceTool&) = delete;
  DRMTraceTool& operator=(const DRMTraceTool&) = delete;

  // Change which debug categories will be written to drm_trace. |categories|
  // must be a bitmask of DRMTraceCategories flags. Setting |categories| to 0
  // resets to the default logging categories.
  bool SetCategories(brillo::ErrorPtr* error, uint32_t categories);

  // Change the size of the buffer holding drm_trace contents. |size_enum| must
  // be a valid value of the DRMTraceSizes enum.
  bool SetSize(brillo::ErrorPtr* error, uint32_t size_enum);

  // Annotate the drm trace log by writing |log| to
  // /sys/kernel/tracing/instances/drm/trace_marker.
  bool AnnotateLog(brillo::ErrorPtr* error, const std::string& log);

  // Copy the log specified by |type_enum| to
  // /var/log/display_debug/$logtype.$datetime
  bool Snapshot(brillo::ErrorPtr* error, uint32_t type_enum);

  // Helper function to write |contents| to the file at |path|.
  static bool WriteToFile(brillo::ErrorPtr* error,
                          const base::FilePath& path,
                          const std::string& contents);

  ~DRMTraceTool() = default;

 private:
  friend class DRMTraceToolTest;

  // From SessionManagerObserverInterface.
  virtual void OnSessionStarted();

  // From SessionManagerObserverInterface.
  virtual void OnSessionStopped();

  // Reset DRM trace parameters to default.
  void SetToDefault();

  // For testing only.
  DRMTraceTool(const base::FilePath& root, LogProvider* provider);

  const base::FilePath root_path_;
  LogProvider* log_provider_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_DRM_TRACE_TOOL_H_
