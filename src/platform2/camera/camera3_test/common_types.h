// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_COMMON_TYPES_H_
#define CAMERA_CAMERA3_TEST_COMMON_TYPES_H_

#include <memory>

#include <camera/camera_metadata.h>

namespace camera3_test {

class ResolutionInfo {
 public:
  ResolutionInfo(int32_t width, int32_t height)
      : width_(width), height_(height) {}

  ResolutionInfo() : width_(0), height_(0) {}

  int32_t Width() const;

  int32_t Height() const;

  int32_t Area() const;

  bool operator==(const ResolutionInfo& resolution) const;

  bool operator<(const ResolutionInfo& resolution) const;

  friend std::ostream& operator<<(std::ostream& out,
                                  const ResolutionInfo& info);

 private:
  int32_t width_, height_;
};

struct CameraMetadataDeleter {
  inline void operator()(camera_metadata_t* metadata) {
    if (metadata) {
      free_camera_metadata(metadata);
    }
  }
};

typedef std::unique_ptr<camera_metadata_t, struct CameraMetadataDeleter>
    ScopedCameraMetadata;

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_COMMON_TYPES_H_
