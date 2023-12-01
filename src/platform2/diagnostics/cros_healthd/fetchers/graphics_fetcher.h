// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_GRAPHICS_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_GRAPHICS_FETCHER_H_

#include <memory>
#include <optional>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/graphics_header.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

class EglManager {
 public:
  EglManager(const EglManager&) = delete;
  EglManager& operator=(const EglManager&) = delete;
  virtual ~EglManager();

  static std::unique_ptr<EglManager> Create();
  virtual ash::cros_healthd::mojom::GLESInfoPtr FetchGLESInfo();
  virtual ash::cros_healthd::mojom::EGLInfoPtr FetchEGLInfo();

 protected:
  EglManager() = default;

 private:
  EGLDisplay egl_display_;
  EGLContext egl_context_;
};

// The GraphicsFetcher class is responsible for gathering graphics info reported
// by cros_healthd.
class GraphicsFetcher final : public BaseFetcher {
 public:
  using BaseFetcher::BaseFetcher;

  // Returns a structure with either the device's graphics data or the error
  // that occurred fetching the information.
  ash::cros_healthd::mojom::GraphicsResultPtr FetchGraphicsInfo(
      std::unique_ptr<EglManager> egl_manager = nullptr);

 private:
  using OptionalProbeErrorPtr =
      std::optional<ash::cros_healthd::mojom::ProbeErrorPtr>;

  OptionalProbeErrorPtr FetchGraphicsInfo(
      std::unique_ptr<EglManager> egl_manager,
      ash::cros_healthd::mojom::GLESInfoPtr* out_gles_info,
      ash::cros_healthd::mojom::EGLInfoPtr* out_egl_info);
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_GRAPHICS_FETCHER_H_
