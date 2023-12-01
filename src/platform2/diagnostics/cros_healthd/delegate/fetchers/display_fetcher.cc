// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/delegate/fetchers/display_fetcher.h"

#include <utility>
#include <vector>

#include "diagnostics/cros_healthd/delegate/utils/display_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

}  // namespace

mojom::DisplayResultPtr GetDisplayInfo() {
  DisplayUtil display_util;
  if (!display_util.Initialize()) {
    return mojom::DisplayResult::NewError(
        mojom::ProbeError::New(mojom::ErrorType::kSystemUtilityError,
                               "Failed to initialize display_util object."));
  }

  auto display_info = mojom::DisplayInfo::New();
  display_info->edp_info = display_util.GetEmbeddedDisplayInfo();

  std::vector<uint32_t> connector_ids =
      display_util.GetExternalDisplayConnectorIDs();
  if (connector_ids.size() != 0) {
    std::vector<mojom::ExternalDisplayInfoPtr> external_display_infos;
    for (const auto& connector_id : connector_ids) {
      external_display_infos.push_back(
          display_util.GetExternalDisplayInfo(connector_id));
    }
    display_info->dp_infos = std::move(external_display_infos);
  }

  return mojom::DisplayResult::NewDisplayInfo(std::move(display_info));
}

}  // namespace diagnostics
