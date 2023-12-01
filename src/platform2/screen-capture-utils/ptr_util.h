// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SCREEN_CAPTURE_UTILS_PTR_UTIL_H_
#define SCREEN_CAPTURE_UTILS_PTR_UTIL_H_

#include <gbm.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#include <memory>
#include <set>

#include <base/files/file.h>

namespace screenshot {

struct DrmModeResDeleter {
  void operator()(drmModeRes* resources) { drmModeFreeResources(resources); }
};
using ScopedDrmModeResPtr = std::unique_ptr<drmModeRes, DrmModeResDeleter>;

struct DrmModeCrtcDeleter {
  void operator()(drmModeCrtc* crtc) { drmModeFreeCrtc(crtc); }
};
using ScopedDrmModeCrtcPtr = std::unique_ptr<drmModeCrtc, DrmModeCrtcDeleter>;

struct DrmModeEncoderDeleter {
  void operator()(drmModeEncoder* encoder) { drmModeFreeEncoder(encoder); }
};
using ScopedDrmModeEncoderPtr =
    std::unique_ptr<drmModeEncoder, DrmModeEncoderDeleter>;

struct DrmModeConnectorDeleter {
  void operator()(drmModeConnector* connector) {
    drmModeFreeConnector(connector);
  }
};
using ScopedDrmModeConnectorPtr =
    std::unique_ptr<drmModeConnector, DrmModeConnectorDeleter>;

struct DrmModeFBDeleter {
  void operator()(drmModeFB* fb) { drmModeFreeFB(fb); }
};
using ScopedDrmModeFBPtr = std::unique_ptr<drmModeFB, DrmModeFBDeleter>;

struct ScopedDrmModeFB2Ptr {
 public:
  // Expectation is that drm_fd owned by Crtc would always outlive this class.
  ScopedDrmModeFB2Ptr(drmModeFB2* fb2, int drm_fd)
      : fb2_(fb2), drm_fd_(drm_fd) {}

  ScopedDrmModeFB2Ptr(ScopedDrmModeFB2Ptr&& source)
      : fb2_(source.fb2_), drm_fd_(source.drm_fd_) {
    source.fb2_ = nullptr;
  }

  ~ScopedDrmModeFB2Ptr() {
    if (fb2_) {
      std::set<int> close_handles;
      for (int i = 0; fb2_->handles[i] && i < GBM_MAX_PLANES; ++i) {
        close_handles.insert(fb2_->handles[i]);
      }
      for (int handle : close_handles) {
        drmCloseBufferHandle(drm_fd_, handle);
      }

      drmModeFreeFB2(fb2_);
    }
  }

  drmModeFB2* get() const { return fb2_; }
  drmModeFB2* operator->() const { return fb2_; }
  explicit operator bool() const noexcept { return fb2_; }

 private:
  drmModeFB2* fb2_;
  const int drm_fd_;
};

struct DrmModePlaneResDeleter {
  void operator()(drmModePlaneRes* res) { drmModeFreePlaneResources(res); }
};
using ScopedDrmPlaneResPtr =
    std::unique_ptr<drmModePlaneRes, DrmModePlaneResDeleter>;

struct DrmModePlaneDeleter {
  void operator()(drmModePlane* plane) { drmModeFreePlane(plane); }
};
using ScopedDrmPlanePtr = std::unique_ptr<drmModePlane, DrmModePlaneDeleter>;

struct DrmModePropertyDeleter {
  void operator()(drmModePropertyRes* prop) { drmModeFreeProperty(prop); }
};
using ScopedDrmPropertyPtr =
    std::unique_ptr<drmModePropertyRes, DrmModePropertyDeleter>;

struct DrmModeObjectPropertiesDeleter {
  void operator()(drmModeObjectProperties* props) {
    drmModeFreeObjectProperties(props);
  }
};
using ScopedDrmObjectPropertiesPtr =
    std::unique_ptr<drmModeObjectProperties, DrmModeObjectPropertiesDeleter>;

struct GbmDeviceDeleter {
  void operator()(gbm_device* device) { gbm_device_destroy(device); }
};
using ScopedGbmDevicePtr = std::unique_ptr<gbm_device, GbmDeviceDeleter>;

struct GbmBoDeleter {
  void operator()(gbm_bo* bo) { gbm_bo_destroy(bo); }
};
using ScopedGbmBoPtr = std::unique_ptr<gbm_bo, GbmBoDeleter>;

}  // namespace screenshot

#endif  // SCREEN_CAPTURE_UTILS_PTR_UTIL_H_
