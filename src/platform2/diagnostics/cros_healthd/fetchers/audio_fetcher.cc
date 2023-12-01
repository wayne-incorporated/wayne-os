// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/audio_fetcher.h"

#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <cras/dbus-proxies.h>

#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

void PopulateMuteInfo(Context* context, mojom::AudioResultPtr& res) {
  mojom::AudioInfoPtr& info = res->get_audio_info();
  int32_t unused_output_volume;
  bool output_mute = false;  // Mute by other system daemons.
  bool input_mute = false;
  bool output_user_mute = false;  // Mute by users.
  brillo::ErrorPtr error;
  if (!context->cras_proxy()->GetVolumeState(&unused_output_volume,
                                             &output_mute, &input_mute,
                                             &output_user_mute, &error)) {
    res->set_error(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        "Failed retrieving mute info from cras: " + error->GetMessage()));
    return;
  }

  info->output_mute = output_mute | output_user_mute;
  info->input_mute = input_mute;
}

void PopulateNodeInfo(Context* context, mojom::AudioResultPtr& res) {
  mojom::AudioInfoPtr& info = res->get_audio_info();
  std::vector<brillo::VariantDictionary> nodes;
  brillo::ErrorPtr error;
  if (!context->cras_proxy()->GetNodeInfos(&nodes, &error)) {
    res->set_error(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        "Failed retrieving node info from cras: " + error->GetMessage()));
    return;
  }

  // There might be no active output / input device such as Chromebox.
  info->output_device_name = std::string("No active output device");
  info->output_volume = 0;
  info->input_device_name = std::string("No active input device");
  info->input_gain = 0;
  info->underruns = 0;
  info->severe_underruns = 0;

  std::vector<mojom::AudioNodeInfoPtr> output_nodes;
  std::vector<mojom::AudioNodeInfoPtr> input_nodes;
  for (const auto& node : nodes) {
    // Important fields are missing.
    if (node.find(cras::kIsInputProperty) == node.end() ||
        node.find(cras::kActiveProperty) == node.end()) {
      continue;
    }

    auto node_info = mojom::AudioNodeInfo::New();
    node_info->id =
        brillo::GetVariantValueOrDefault<uint64_t>(node, cras::kIdProperty);
    node_info->name = brillo::GetVariantValueOrDefault<std::string>(
        node, cras::kNameProperty);
    node_info->device_name = brillo::GetVariantValueOrDefault<std::string>(
        node, cras::kDeviceNameProperty);
    node_info->active =
        brillo::GetVariantValueOrDefault<bool>(node, cras::kActiveProperty);
    node_info->node_volume = brillo::GetVariantValueOrDefault<uint64_t>(
        node, cras::kNodeVolumeProperty);
    node_info->input_node_gain = brillo::GetVariantValueOrDefault<uint32_t>(
        node, cras::kInputNodeGainProperty);

    if (!brillo::GetVariantValueOrDefault<bool>(node, cras::kIsInputProperty)) {
      if (node_info->active) {
        // Active output node.
        info->output_device_name = node_info->name;
        info->output_volume = node_info->node_volume;
        if (node.find(cras::kNumberOfUnderrunsProperty) != node.end()) {
          info->underruns = brillo::GetVariantValueOrDefault<uint32_t>(
              node, cras::kNumberOfUnderrunsProperty);
        }
        if (node.find(cras::kNumberOfSevereUnderrunsProperty) != node.end()) {
          info->severe_underruns = brillo::GetVariantValueOrDefault<uint32_t>(
              node, cras::kNumberOfSevereUnderrunsProperty);
        }
      }
      output_nodes.push_back(std::move(node_info));
    } else {
      if (node_info->active) {
        // Active input node.
        info->input_device_name = node_info->name;
        info->input_gain = node_info->input_node_gain;
      }
      input_nodes.push_back(std::move(node_info));
    }
  }

  info->output_nodes = std::move(output_nodes);
  info->input_nodes = std::move(input_nodes);
}

mojom::AudioResultPtr FetchAudioInfoInner(Context* context) {
  auto res = mojom::AudioResult::NewAudioInfo(mojom::AudioInfo::New());

  PopulateMuteInfo(context, res);
  if (res->is_error())
    return res;

  PopulateNodeInfo(context, res);
  return res;
}

}  // namespace

void FetchAudioInfo(Context* context, FetchAudioInfoCallback callback) {
  std::move(callback).Run(FetchAudioInfoInner(context));
}

}  // namespace diagnostics
