// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/ssfc/ssfc_prober.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "rmad/system/runtime_probe_client_impl.h"
#include "rmad/utils/cbi_utils_impl.h"
#include "rmad/utils/cros_config_utils_impl.h"
#include "rmad/utils/dbus_utils.h"

namespace rmad {

SsfcProberImpl::SsfcProberImpl() {
  runtime_probe_client_ =
      std::make_unique<RuntimeProbeClientImpl>(GetSystemBus());
  cbi_utils_ = std::make_unique<CbiUtilsImpl>();
  cros_config_utils_ = std::make_unique<CrosConfigUtilsImpl>();
  Initialize();
}

SsfcProberImpl::SsfcProberImpl(
    std::unique_ptr<RuntimeProbeClient> runtime_probe_client,
    std::unique_ptr<CbiUtils> cbi_utils,
    std::unique_ptr<CrosConfigUtils> cros_config_utils)
    : runtime_probe_client_(std::move(runtime_probe_client)),
      cbi_utils_(std::move(cbi_utils)),
      cros_config_utils_(std::move(cros_config_utils)) {
  Initialize();
}

void SsfcProberImpl::Initialize() {
  RmadConfig rmad_config;
  if (cros_config_utils_->GetRmadConfig(&rmad_config) &&
      !rmad_config.ssfc.component_type_configs.empty()) {
    ssfc_required_ = true;
    ssfc_config_ = rmad_config.ssfc;
  } else {
    ssfc_required_ = false;
  }
}

bool SsfcProberImpl::ProbeSsfc(uint32_t* ssfc) const {
  if (!IsSsfcRequired()) {
    return false;
  }

  std::vector<std::pair<RmadComponent, std::string>> runtime_probed_components;
  if (!runtime_probe_client_->ProbeSsfcComponents(
          /*use_customized_identifier=*/false, &runtime_probed_components)) {
    return false;
  }

  // Get existing SSFC, which might not exist.
  uint32_t probed_ssfc = 0;
  cbi_utils_->GetSsfc(&probed_ssfc);
  probed_ssfc &= ssfc_config_.mask;

  // Update SSFC by probed results.
  for (const auto& component_type_config :
       ssfc_config_.component_type_configs) {
    const auto& probeable_components =
        component_type_config.probeable_components;
    // Iterator of probed component under the component type.
    auto probed_it = probeable_components.cend();
    for (const auto& [component, identifier] : runtime_probed_components) {
      if (auto it = probeable_components.find(identifier);
          it != probeable_components.cend()) {
        // There could be multiple probed results that map to the same component
        // depending on how the probe statement is written, but at most one
        // component under the component type should be probed.
        if (probed_it != it && probed_it != probeable_components.cend()) {
          LOG(ERROR) << "Failed to probe component type "
                     << component_type_config.component_type
                     << ": multiple components under the same type: "
                     << probed_it->first << " and " << it->first;
          return false;
        }
        probed_it = it;
      }
    }
    if (probed_it == probeable_components.cend()) {
      probed_ssfc |= component_type_config.default_value;
    } else {
      probed_ssfc |= probed_it->second;
    }
  }

  *ssfc = probed_ssfc;
  return true;
}

}  // namespace rmad
