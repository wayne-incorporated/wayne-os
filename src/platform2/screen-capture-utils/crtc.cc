// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "screen-capture-utils/crtc.h"

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/stl_util.h>

namespace screenshot {

namespace {

constexpr const char kDrmDeviceDir[] = "/dev/dri";
constexpr const char kDrmDeviceGlob[] = "card?";

float FixedPoint1616ToFloat(uint32_t n) {
  float result = (n & 0xFFFF0000) >> 16;
  result += (n & 0xFFFF) / 65536.0f;
  return result;
}

bool PopulatePlaneConfiguration(int fd,
                                uint32_t plane_id,
                                PlaneConfiguration* conf) {
  // TODO(andrescj): Handle rotation.
  std::map<std::string, uint64_t> interesting_props{
      {"CRTC_X", 0}, {"CRTC_Y", 0}, {"CRTC_W", 0}, {"CRTC_H", 0},
      {"SRC_X", 0},  {"SRC_Y", 0},  {"SRC_W", 0},  {"SRC_H", 0}};

  ScopedDrmObjectPropertiesPtr props(
      drmModeObjectGetProperties(fd, plane_id, DRM_MODE_OBJECT_PLANE));
  if (!props) {
    return false;
  }

  int found = 0;
  for (int i = 0; i < props->count_props; i++) {
    ScopedDrmPropertyPtr prop(drmModeGetProperty(fd, props->props[i]));
    if (!prop) {
      continue;
    }

    if (interesting_props.find(prop->name) != interesting_props.end()) {
      interesting_props[prop->name] = props->prop_values[i];
      found++;
    }
  }

  if (found != interesting_props.size()) {
    return false;
  }

  conf->x = static_cast<int32_t>(interesting_props["CRTC_X"]);
  conf->y = static_cast<int32_t>(interesting_props["CRTC_Y"]);
  conf->w = static_cast<uint32_t>(interesting_props["CRTC_W"]);
  conf->h = static_cast<uint32_t>(interesting_props["CRTC_H"]);
  conf->crop_x = FixedPoint1616ToFloat(interesting_props["SRC_X"]);
  conf->crop_y = FixedPoint1616ToFloat(interesting_props["SRC_Y"]);
  conf->crop_w = FixedPoint1616ToFloat(interesting_props["SRC_W"]);
  conf->crop_h = FixedPoint1616ToFloat(interesting_props["SRC_H"]);
  return true;
}

std::vector<std::unique_ptr<Crtc>> GetConnectedCrtcs() {
  std::vector<std::unique_ptr<Crtc>> crtcs;

  std::vector<base::FilePath> paths;
  {
    base::FileEnumerator lister(base::FilePath(kDrmDeviceDir), false,
                                base::FileEnumerator::FILES, kDrmDeviceGlob);
    for (base::FilePath name = lister.Next(); !name.empty();
         name = lister.Next()) {
      paths.emplace_back(name);
    }
  }
  std::sort(paths.begin(), paths.end());

  for (base::FilePath path : paths) {
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                              base::File::FLAG_WRITE);
    if (!file.IsValid())
      continue;

    // Set CAP_ATOMIC so we can query all planes and plane properties.
    bool atomic_modeset =
        drmSetClientCap(file.GetPlatformFile(), DRM_CLIENT_CAP_ATOMIC, 1) == 0;

    ScopedDrmModeResPtr resources(drmModeGetResources(file.GetPlatformFile()));
    if (!resources)
      continue;

    for (int index_connector = 0; index_connector < resources->count_connectors;
         ++index_connector) {
      ScopedDrmModeConnectorPtr connector(drmModeGetConnector(
          file.GetPlatformFile(), resources->connectors[index_connector]));
      if (!connector || connector->encoder_id == 0)
        continue;

      ScopedDrmModeEncoderPtr encoder(
          drmModeGetEncoder(file.GetPlatformFile(), connector->encoder_id));
      if (!encoder || encoder->crtc_id == 0)
        continue;

      ScopedDrmModeCrtcPtr crtc(
          drmModeGetCrtc(file.GetPlatformFile(), encoder->crtc_id));
      if (!crtc || !crtc->mode_valid || crtc->buffer_id == 0)
        continue;

      ScopedDrmModeFB2Ptr fb2(
          drmModeGetFB2(file.GetPlatformFile(), crtc->buffer_id),
          file.GetPlatformFile());

      if (!fb2) {
        LOG(ERROR) << "getfb2 failed";
        continue;
      }

      std::unique_ptr<Crtc> res_crtc;

      // Keep around a file for next display if needed.
      base::File file_dup = file.Duplicate();
      if (!file_dup.IsValid())
        continue;

      // Multiplane is only supported when atomic_modeset is available. Obtain
      // the |plane_res_| for later use.
      if (atomic_modeset) {
        ScopedDrmPlaneResPtr plane_res(
            drmModeGetPlaneResources(file.GetPlatformFile()));
        CHECK(plane_res) << " Failed to get plane resources";
        res_crtc = std::make_unique<Crtc>(std::move(file), std::move(connector),
                                          std::move(encoder), std::move(crtc),
                                          std::move(fb2), std::move(plane_res));
      } else {
        res_crtc = std::make_unique<Crtc>(std::move(file), std::move(connector),
                                          std::move(encoder), std::move(crtc),
                                          std::move(fb2), nullptr);
      }

      file = std::move(file_dup);
      crtcs.emplace_back(std::move(res_crtc));
    }
  }

  return crtcs;
}

}  // namespace

Crtc::Crtc(base::File file,
           ScopedDrmModeConnectorPtr connector,
           ScopedDrmModeEncoderPtr encoder,
           ScopedDrmModeCrtcPtr crtc,
           ScopedDrmModeFB2Ptr fb2,
           ScopedDrmPlaneResPtr plane_res)
    : file_(std::move(file)),
      connector_(std::move(connector)),
      encoder_(std::move(encoder)),
      crtc_(std::move(crtc)),
      fb2_(std::move(fb2)),
      plane_res_(std::move(plane_res)) {}

bool Crtc::IsInternalDisplay() const {
  switch (connector_->connector_type) {
    case DRM_MODE_CONNECTOR_eDP:
    case DRM_MODE_CONNECTOR_LVDS:
    case DRM_MODE_CONNECTOR_DSI:
    case DRM_MODE_CONNECTOR_VIRTUAL:
      return true;
    default:
      return false;
  }
}

std::unique_ptr<Crtc> CrtcFinder::Find() const {
  auto crtcs = GetConnectedCrtcs();
  for (auto& crtc : crtcs) {
    if (MatchesSpec(crtc.get()))
      return std::move(crtc);
  }
  return nullptr;
}

bool CrtcFinder::MatchesSpec(const Crtc* crtc) const {
  switch (spec_) {
    case Spec::kAnyDisplay:
      return true;
    case Spec::kInternalDisplay:
      return crtc->IsInternalDisplay();
    case Spec::kExternalDisplay:
      return !crtc->IsInternalDisplay();
    case Spec::kById:
      return crtc->crtc()->crtc_id == crtc_id_;
  }
  NOTREACHED() << "Invalid spec";
  return false;
}

std::vector<Crtc::PlaneInfo> Crtc::GetConnectedPlanes() const {
  CHECK(fb2())
      << "This code path is supported only if drmModeGetFB2() succeeded "
         "for the CRTC.";
  std::vector<Crtc::PlaneInfo> planes;
  if (!plane_res_.get()) {
    // Return the empty list if we decided not to query the plane resources or
    // if doing so failed.
    return planes;
  }
  for (uint32_t i = 0; i < plane_res_->count_planes; i++) {
    ScopedDrmPlanePtr plane(
        drmModeGetPlane(file_.GetPlatformFile(), plane_res_->planes[i]));
    if (plane->crtc_id != crtc_->crtc_id) {
      continue;
    }

    PlaneConfiguration conf{};
    bool res = PopulatePlaneConfiguration(file_.GetPlatformFile(),
                                          plane->plane_id, &conf);
    if (!res) {
      LOG(WARNING) << "Failed to query plane position, skipping.\n";
      continue;
    }
    ScopedDrmModeFB2Ptr fb_info(
        drmModeGetFB2(file_.GetPlatformFile(), plane->fb_id),
        file_.GetPlatformFile());
    if (!fb_info) {
      LOG(WARNING) << "Failed to query plane fb info, skipping.\n";
      continue;
    }
    planes.emplace_back(std::make_pair(std::move(fb_info), conf));
  }
  return planes;
}

}  // namespace screenshot
