// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#ifndef CAMERA_CAMERA3_TEST_CAMERA3_EXIF_VALIDATOR_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_EXIF_VALIDATOR_H_

#include <base/logging.h>
#include <exif-data.h>

#include "camera3_test/camera3_device_fixture.h"

namespace camera3_test {

class Camera3ExifValidator {
 public:
  struct JpegExifInfo {
    const cros::ScopedBufferHandle& buffer_handle;
    size_t buffer_size;
    void* buffer_addr;
    ResolutionInfo jpeg_resolution;
    ExifData* exif_data;
    JpegExifInfo(const cros::ScopedBufferHandle& buffer, size_t size);
    ~JpegExifInfo();
    bool Initialize();
  };

  struct ExifTestData {
    ResolutionInfo thumbnail_resolution;
    int32_t orientation;
    uint8_t jpeg_quality;
    uint8_t thumbnail_quality;
  };

  explicit Camera3ExifValidator(const Camera3Device::StaticInfo& cam_info)
      : cam_info_(cam_info) {}
  Camera3ExifValidator(const Camera3ExifValidator&) = delete;
  Camera3ExifValidator& operator=(const Camera3ExifValidator&) = delete;

  void ValidateExifKeys(const ResolutionInfo& jpeg_resolution,
                        const ExifTestData& exif_test_data,
                        const cros::ScopedBufferHandle& buffer,
                        size_t buffer_size,
                        const camera_metadata_t& metadata,
                        const time_t& date_time) const;
  int getExifOrientation(const cros::ScopedBufferHandle& buffer,
                         size_t buffer_size);

 protected:
  const Camera3Device::StaticInfo& cam_info_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_EXIF_VALIDATOR_H_
