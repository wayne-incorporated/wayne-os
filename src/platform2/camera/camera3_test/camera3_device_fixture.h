// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_FIXTURE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_FIXTURE_H_

#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <hardware/camera3.h>
#include <hardware/hardware.h>

#include "camera3_test/camera3_device.h"
#include "camera3_test/camera3_module_fixture.h"
#include "camera3_test/camera3_test_gralloc.h"
#include "camera3_test/common_types.h"
#include "common/camera_buffer_handle.h"

namespace camera3_test {

template <typename T>
int UpdateMetadata(uint32_t tag,
                   const T* data,
                   size_t data_count,
                   ScopedCameraMetadata* metadata_unique_ptr) {
  android::CameraMetadata metadata(metadata_unique_ptr->release());
  int result = metadata.update(tag, data, data_count);
  metadata_unique_ptr->reset(metadata.release());
  return result;
}

class Camera3DeviceFixture : public testing::Test {
 public:
  explicit Camera3DeviceFixture(int cam_id) : cam_device_(cam_id) {}

  Camera3DeviceFixture(const Camera3DeviceFixture&) = delete;
  Camera3DeviceFixture& operator=(const Camera3DeviceFixture&) = delete;

  void SetUp() override;

  void TearDown() override;

 protected:
  Camera3Module cam_module_;

  Camera3Device cam_device_;

 private:
  // Process result metadata and/or output buffers. Tests can override this
  // function to handle metadata/buffers to suit their purpose. Note that
  // the metadata |metadata| and output buffers kept in |buffers| will be
  // freed after returning from this call; a test can "std::move" the unique
  // pointers to keep the metadata and buffer.
  virtual void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) {}

  // Process partial metadata. Tests can override this function to handle all
  // received partial metadata.
  virtual void ProcessPartialMetadata(
      std::vector<ScopedCameraMetadata>* partial_metadata) {}
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_DEVICE_FIXTURE_H_
