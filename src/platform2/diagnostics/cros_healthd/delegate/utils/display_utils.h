// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_DISPLAY_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_DISPLAY_UTILS_H_

#include <memory>
#include <string>
#include <vector>
#include <xf86drm.h>
#include <xf86drmMode.h>

#include <base/files/file.h>

#include "diagnostics/cros_healthd/delegate/utils/edid.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

class DisplayUtil {
 public:
  DisplayUtil() = default;
  DisplayUtil(const DisplayUtil& oth) = delete;
  DisplayUtil(DisplayUtil&& oth) = delete;
  ~DisplayUtil() = default;

  struct DrmModeResDeleter {
    void operator()(drmModeRes* resources) { drmModeFreeResources(resources); }
  };

  struct DrmModeConnectorDeleter {
    void operator()(drmModeConnector* connector) {
      drmModeFreeConnector(connector);
    }
  };

  struct DrmModePropertyDeleter {
    void operator()(drmModePropertyRes* prop) { drmModeFreeProperty(prop); }
  };

  struct DrmModePropertyBlobDeleter {
    void operator()(drmModePropertyBlobRes* prop) {
      drmModeFreePropertyBlob(prop);
    }
  };

  struct DrmModeEncoderDeleter {
    void operator()(drmModeEncoder* encoder) { drmModeFreeEncoder(encoder); }
  };

  struct DrmModeCrtcDeleter {
    void operator()(drmModeCrtc* crtc) { drmModeFreeCrtc(crtc); }
  };

  using ScopedDrmModeResPtr = std::unique_ptr<drmModeRes, DrmModeResDeleter>;
  using ScopedDrmModeConnectorPtr =
      std::unique_ptr<drmModeConnector, DrmModeConnectorDeleter>;
  using ScopedDrmPropertyPtr =
      std::unique_ptr<drmModePropertyRes, DrmModePropertyDeleter>;
  using ScopedDrmPropertyBlobPtr =
      std::unique_ptr<drmModePropertyBlobRes, DrmModePropertyBlobDeleter>;
  using ScopedDrmModeEncoderPtr =
      std::unique_ptr<drmModeEncoder, DrmModeEncoderDeleter>;
  using ScopedDrmModeCrtcPtr = std::unique_ptr<drmModeCrtc, DrmModeCrtcDeleter>;

  bool Initialize();
  std::optional<uint32_t> GetEmbeddedDisplayConnectorID();
  std::vector<uint32_t> GetExternalDisplayConnectorIDs();
  void FillPrivacyScreenInfo(const uint32_t connector_id,
                             bool* privacy_screen_supported,
                             bool* privacy_screen_enabled);
  bool FillDisplaySize(const uint32_t connector_id,
                       uint32_t* width,
                       uint32_t* height);
  bool FillDisplayResolution(const uint32_t connector_id,
                             uint32_t* horizontal,
                             uint32_t* vertical);
  bool FillEdidInfo(const uint32_t connector_id, EdidInfo* info);
  bool FillDisplayRefreshRate(const uint32_t connector_id,
                              double* refresh_rate);
  std::vector<uint32_t> GetHdmiConnectorIDs();
  ash::cros_healthd::mojom::ExternalDisplayInfoPtr GetExternalDisplayInfo(
      const uint32_t connector_id);
  ash::cros_healthd::mojom::EmbeddedDisplayInfoPtr GetEmbeddedDisplayInfo();

 private:
  // This function iterates all the properties in |connector| and find the
  // property with |name|. When it finds it, it stores the property into
  // |prop| and return its index. If it fails to find it, -1 is returned.
  int GetDrmProperty(const ScopedDrmModeConnectorPtr& connector,
                     const std::string& name,
                     ScopedDrmPropertyPtr* prop);
  std::string GetEnumName(const ScopedDrmPropertyPtr& prop, uint32_t value);
  DisplayUtil::ScopedDrmModeCrtcPtr GetDrmCrtc(const uint32_t connector_id);
  DisplayUtil::ScopedDrmPropertyBlobPtr GetDrmPropertyBlob(
      const uint32_t connector_id, const std::string& name);

  base::File device_file_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_DISPLAY_UTILS_H_
