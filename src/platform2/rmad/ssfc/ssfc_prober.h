// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SSFC_SSFC_PROBER_H_
#define RMAD_SSFC_SSFC_PROBER_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "rmad/system/runtime_probe_client.h"
#include "rmad/utils/cbi_utils.h"
#include "rmad/utils/cros_config_utils.h"

namespace rmad {

class SsfcProber {
 public:
  SsfcProber() = default;
  virtual ~SsfcProber() = default;

  virtual bool IsSsfcRequired() const = 0;
  virtual bool ProbeSsfc(uint32_t* ssfc) const = 0;
};

class SsfcProberImpl : public SsfcProber {
 public:
  SsfcProberImpl();
  // Used to inject mocked |RuntimeProbeClient|, |CbiUtils| and
  // |CrosConfigUtils| for testing.
  explicit SsfcProberImpl(
      std::unique_ptr<RuntimeProbeClient> runtime_probe_client,
      std::unique_ptr<CbiUtils> cbi_utils,
      std::unique_ptr<CrosConfigUtils> cros_config_utils);
  ~SsfcProberImpl() override = default;

  bool IsSsfcRequired() const override { return ssfc_required_; }
  bool ProbeSsfc(uint32_t* ssfc) const override;

 private:
  void Initialize();

  std::unique_ptr<RuntimeProbeClient> runtime_probe_client_;
  std::unique_ptr<CbiUtils> cbi_utils_;
  std::unique_ptr<CrosConfigUtils> cros_config_utils_;

  bool ssfc_required_;
  SsfcConfig ssfc_config_;
};

}  // namespace rmad

#endif  // RMAD_SSFC_SSFC_PROBER_H_
