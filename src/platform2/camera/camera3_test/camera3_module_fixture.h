// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_MODULE_FIXTURE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_MODULE_FIXTURE_H_

#include <dlfcn.h>

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <base/synchronization/lock.h>
#include <cros-camera/camera_thread.h>
#include <gtest/gtest.h>

#include "camera3_test/camera3_device_connector.h"
#include "camera3_test/camera3_module_connector.h"
#include "camera3_test/common_types.h"
#include "cros-camera/cros_camera_hal.h"

namespace camera3_test {

const int kMaxNumCameras = 2;
const size_t kNumOfElementsInStreamConfigEntry = 4;
enum {
  STREAM_CONFIG_FORMAT_INDEX,
  STREAM_CONFIG_WIDTH_INDEX,
  STREAM_CONFIG_HEIGHT_INDEX,
  STREAM_CONFIG_DIRECTION_INDEX,
  STREAM_CONFIG_STALL_DURATION_INDEX = STREAM_CONFIG_DIRECTION_INDEX,
  STREAM_CONFIG_MIN_DURATION_INDEX = STREAM_CONFIG_DIRECTION_INDEX
};

cros::cros_camera_hal_t* GetCrosCameraHal();

// Returns true if the |actual_level| is equal to or beyond the
// |required_level|.
bool isHardwareLevelSupported(uint8_t actual_level, uint8_t required_level);

// Get recording parameter list of camera id, width, height and frame rate
std::vector<std::tuple<int, int32_t, int32_t, float, bool>>
ParseRecordingParams();

class CameraModuleCallbacksHandler {
 public:
  static void camera_device_status_change(
      const camera_module_callbacks_t* callbacks,
      int camera_id,
      int new_status);

  static void torch_mode_status_change(
      const camera_module_callbacks_t* callbacks,
      const char* camera_id,
      int new_status);

  static CameraModuleCallbacksHandler* GetInstance();

  bool IsExternalCameraPresent(int camera_id);

 private:
  void CameraDeviceStatusChange(int camera_id,
                                camera_device_status_t new_status);

  void TorchModeStatusChange(int camera_id, torch_mode_status_t new_status);

  // All operations are sequenced by |lock_|.
  base::Lock lock_;

  std::map<int, camera_device_status_t> device_status_;
};

struct CameraModuleCallbacksAux : camera_module_callbacks_t {
  static CameraModuleCallbacksAux* GetInstance();

  CameraModuleCallbacksAux();

  CameraModuleCallbacksHandler* handler;
};

class Camera3Module {
 public:
  Camera3Module();
  Camera3Module(const Camera3Module&) = delete;
  Camera3Module& operator=(const Camera3Module&) = delete;

  // Get number of cameras
  int GetNumberOfCameras();

  // Get list of camera IDs
  std::vector<int> GetCameraIds();

  // Get list of test camera IDs if specify in cmdline args, or default use
  // |GetCameraIds|
  std::vector<int> GetTestCameraIds();

  // Check if a stream format is supported
  bool IsFormatAvailable(int cam_id, int format);

  // Get camera information
  int GetCameraInfo(int cam_id, camera_info* info);

  // Open camera device
  std::unique_ptr<DeviceConnector> OpenDevice(int cam_id);

  // Get vendor tag by the tag name; False is returned if not found.
  bool GetVendorTagByName(const std::string name, uint32_t* tag);

  // Get the image output formats in this stream configuration
  std::vector<int32_t> GetOutputFormats(int cam_id);

  // Get the image output resolutions in this stream configuration
  std::vector<ResolutionInfo> GetSortedOutputResolutions(int cam_id,
                                                         int32_t format);

  // Get the stall duration for the format/size combination (in nanoseconds)
  int64_t GetOutputStallDuration(int cam_id,
                                 int32_t format,
                                 const ResolutionInfo& resolution);

  //  Get the minimum frame duration
  int64_t GetOutputMinFrameDuration(int cam_id,
                                    int32_t format,
                                    const ResolutionInfo& resolution);

 private:
  void GetStreamConfigEntry(int cam_id,
                            int32_t key,
                            camera_metadata_ro_entry_t* entry);

  int64_t GetOutputKeyParameterI64(int cam_id,
                                   int32_t format,
                                   const ResolutionInfo& resolution,
                                   int32_t key,
                                   int32_t index);

  std::unique_ptr<ModuleConnector> cam_module_connector_;

  // Id of cameras to be tested exclusively. Empty vector for test all available
  // cameras.
  std::vector<int> test_camera_ids_;
};

class Camera3ModuleFixture : public testing::Test {
 public:
  Camera3ModuleFixture() = default;
  Camera3ModuleFixture(const Camera3ModuleFixture&) = delete;
  Camera3ModuleFixture& operator=(const Camera3ModuleFixture&) = delete;

 protected:
  Camera3Module cam_module_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_MODULE_FIXTURE_H_
