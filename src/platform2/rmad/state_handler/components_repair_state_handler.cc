// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/components_repair_state_handler.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/system/cryptohome_client_impl.h"
#include "rmad/system/runtime_probe_client_impl.h"
#include "rmad/utils/dbus_utils.h"
#include "rmad/utils/write_protect_utils_impl.h"

// Used as an unique identifier for supported components.
using ComponentKey = std::pair<rmad::RmadComponent, std::string>;

// Just for convenience.
using ComponentRepairStatus =
    rmad::ComponentsRepairState::ComponentRepairStatus;
using RepairStatus = ComponentRepairStatus::RepairStatus;

namespace std {

// Hash definition for |ComponentKey|, so we can use it in std::unordered_map.
template <>
struct std::hash<ComponentKey> {
  std::size_t operator()(const ComponentKey& key) const {
    return std::hash<uint32_t>()(key.first) ^
           std::hash<std::string>()(key.second);
  }
};

}  // namespace std

namespace rmad {

namespace {

const std::unordered_set<RmadComponent> kProbeableComponents = {
    RMAD_COMPONENT_BATTERY,  RMAD_COMPONENT_STORAGE,
    RMAD_COMPONENT_CAMERA,   RMAD_COMPONENT_STYLUS,
    RMAD_COMPONENT_TOUCHPAD, RMAD_COMPONENT_TOUCHSCREEN,
    RMAD_COMPONENT_DRAM,     RMAD_COMPONENT_DISPLAY_PANEL,
    RMAD_COMPONENT_CELLULAR, RMAD_COMPONENT_ETHERNET,
    RMAD_COMPONENT_WIRELESS,
};

const std::unordered_set<RmadComponent> kUnprobeableComponents = {
    RMAD_COMPONENT_KEYBOARD,           RMAD_COMPONENT_POWER_BUTTON,
    RMAD_COMPONENT_BASE_ACCELEROMETER, RMAD_COMPONENT_LID_ACCELEROMETER,
    RMAD_COMPONENT_BASE_GYROSCOPE,     RMAD_COMPONENT_LID_GYROSCOPE,
    RMAD_COMPONENT_AUDIO_CODEC,
};

ComponentRepairStatus CreateComponentRepairStatus(
    RmadComponent component,
    RepairStatus repair_status,
    const std::string& identifier) {
  ComponentRepairStatus component_repair_status;
  component_repair_status.set_component(component);
  component_repair_status.set_repair_status(repair_status);
  component_repair_status.set_identifier(identifier);
  return component_repair_status;
}

// Convert the list of |ComponentRepairStatus| in |state| to a map using the
// pair (component, identifier) as the key. There might be collisions, e.g. DRAM
// has multiple probe entries for each slots, but we still view them as the same
// DRAM component.
std::unordered_map<ComponentKey, RepairStatus> ConvertStateToDictionary(
    const RmadState& state) {
  std::unordered_map<ComponentKey, RepairStatus> component_map;
  if (state.has_components_repair()) {
    const ComponentsRepairState& components_repair = state.components_repair();
    for (int i = 0; i < components_repair.components_size(); ++i) {
      const ComponentRepairStatus& component_repair_status =
          components_repair.components(i);
      if (component_repair_status.component() == RMAD_COMPONENT_UNKNOWN) {
        LOG(WARNING) << "RmadState component missing |component| field.";
        continue;
      }
      // |mainboard_rework| and replaced component should not exist at the same
      // time.
      if (components_repair.mainboard_rework() &&
          component_repair_status.repair_status() ==
              ComponentRepairStatus::RMAD_REPAIR_STATUS_REPLACED) {
        LOG(ERROR) << "No individual component should be replaced when the "
                   << "mainboard is reworked";
      }
      component_map[std::make_pair(component_repair_status.component(),
                                   component_repair_status.identifier())] =
          component_repair_status.repair_status();
    }
  }
  return component_map;
}

// Convert a map of {(component, identifier), repair_status} to a |RmadState|.
RmadState ConvertDictionaryToState(
    const std::unordered_map<ComponentKey, RepairStatus>& component_map,
    bool mainboard_rework) {
  auto components_repair = std::make_unique<ComponentsRepairState>();
  for (const auto& [key, repair_status] : component_map) {
    RmadComponent component = key.first;
    const std::string& identifier = key.second;
    if (component == RMAD_COMPONENT_UNKNOWN) {
      LOG(WARNING) << "List contains UNKNOWN component";
      continue;
    }
    // |mainboard_rework| and replaced component should not exist at the same
    // time.
    if (mainboard_rework &&
        repair_status == ComponentRepairStatus::RMAD_REPAIR_STATUS_REPLACED) {
      LOG(ERROR) << "No individual component should be replaced when the "
                 << "mainboard is reworked";
    }
    *(components_repair->add_components()) =
        CreateComponentRepairStatus(component, repair_status, identifier);
  }
  components_repair->set_mainboard_rework(mainboard_rework);

  RmadState state;
  state.set_allocated_components_repair(components_repair.release());
  return state;
}

}  // namespace

ComponentsRepairStateHandler::ComponentsRepairStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback)
    : BaseStateHandler(json_store, daemon_callback), active_(false) {
  cryptohome_client_ = std::make_unique<CryptohomeClientImpl>(GetSystemBus());
  runtime_probe_client_ =
      std::make_unique<RuntimeProbeClientImpl>(GetSystemBus());
  write_protect_utils_ = std::make_unique<WriteProtectUtilsImpl>();
}

ComponentsRepairStateHandler::ComponentsRepairStateHandler(
    scoped_refptr<JsonStore> json_store,
    scoped_refptr<DaemonCallback> daemon_callback,
    std::unique_ptr<CryptohomeClient> cryptohome_client,
    std::unique_ptr<RuntimeProbeClient> runtime_probe_client,
    std::unique_ptr<WriteProtectUtils> write_protect_utils)
    : BaseStateHandler(json_store, daemon_callback),
      active_(false),
      cryptohome_client_(std::move(cryptohome_client)),
      runtime_probe_client_(std::move(runtime_probe_client)),
      write_protect_utils_(std::move(write_protect_utils)) {}

RmadErrorCode ComponentsRepairStateHandler::InitializeState() {
  // Probing takes a lot of time. Early return to avoid probing again if we are
  // already in this state.
  if (active_) {
    return RMAD_ERROR_OK;
  }

  if (!state_.has_components_repair() && !RetrieveState()) {
    state_.mutable_components_repair()->set_mainboard_rework(false);
  }

  // Initialize helper data structures.
  std::unordered_map<ComponentKey, RepairStatus> old_component_map =
      ConvertStateToDictionary(state_);
  std::unordered_map<RmadComponent, bool> is_component_probed;
  for (RmadComponent component : kProbeableComponents) {
    is_component_probed[component] = false;
  }

  // Call runtime_probe to get all probed components.
  ComponentsWithIdentifier probed_components;
  if (!runtime_probe_client_->ProbeCategories({}, true, &probed_components)) {
    LOG(ERROR) << "Failed to get probe result from runtime_probe";
    return RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED;
  }

  // Create a new map of component repair status using runtime_probe results.
  // 1. If a probed component is found in the previous probe result, preserve
  //    the repair status. Otherwise mark it as UNKNOWN.
  // 2. If a probeable component type doesn't appear in the probe result, add an
  //    entry with empty identifier and MISSING status.
  // 3. For each unprobeable component type, add an entry with empty identifier.
  //    Preserve the previous repair status is it exists, otherwise mark the
  //    status as UNKNOWN.
  std::unordered_map<ComponentKey, RepairStatus> new_component_map;
  for (const auto& key : probed_components) {
    RmadComponent component = key.first;
    CHECK_GT(kProbeableComponents.count(component), 0);
    is_component_probed[component] = true;
    if (old_component_map.count(key) > 0) {
      new_component_map[key] = old_component_map[key];
    } else {
      new_component_map[key] =
          ComponentRepairStatus::RMAD_REPAIR_STATUS_UNKNOWN;
    }
  }
  for (RmadComponent component : kProbeableComponents) {
    if (!is_component_probed[component]) {
      new_component_map[std::make_pair(component, "")] =
          ComponentRepairStatus::RMAD_REPAIR_STATUS_MISSING;
    }
  }
  for (RmadComponent component : kUnprobeableComponents) {
    auto key = std::make_pair(component, "");
    if (old_component_map.count(key) > 0) {
      new_component_map[key] = old_component_map[key];
    } else {
      new_component_map[key] =
          ComponentRepairStatus::RMAD_REPAIR_STATUS_UNKNOWN;
    }
  }

  state_ = ConvertDictionaryToState(
      new_component_map, state_.components_repair().mainboard_rework());
  active_ = true;
  return RMAD_ERROR_OK;
}

void ComponentsRepairStateHandler::CleanUpState() {
  active_ = false;
}

BaseStateHandler::GetNextStateCaseReply
ComponentsRepairStateHandler::GetNextStateCase(const RmadState& state) {
  if (!ApplyUserSelection(state)) {
    return NextStateCaseWrapper(RMAD_ERROR_REQUEST_INVALID);
  }

  // Store the state to storage to keep user's selection.
  StoreState();
  StoreVars();

  // In the case of MLB repair, the device always goes to a different owner so
  // we skip DeviceDestination and WipeSelection states.
  // 1. Different owner + CCD blocked:
  //    Mandatory RSU. Go straight to RSU state.
  // 2. Different owner + CCD not blocked:
  //    Must wipe the device. Also skip WipeSelection state and go to
  //    WpDisableMethod state.
  if (state_.components_repair().mainboard_rework()) {
    json_store_->SetValue(kSameOwner, false);
    MetricsUtils::SetMetricsValue(
        json_store_, kMetricsReturningOwner,
        ReturningOwner_Name(
            ReturningOwner::RMAD_RETURNING_OWNER_DIFFERENT_OWNER));
    json_store_->SetValue(kWpDisableRequired, true);
    json_store_->SetValue(kWipeDevice, true);
    if (cryptohome_client_->IsCcdBlocked()) {
      // Case 1.
      json_store_->SetValue(kCcdBlocked, true);
      return NextStateCaseWrapper(RmadState::StateCase::kWpDisableRsu);
    } else {
      // Case 2.
      json_store_->SetValue(kCcdBlocked, false);
      // If HWWP is already disabled, assume the user will select the physical
      // method and go directly to WpDisablePhysical state.
      if (bool hwwp_enabled;
          write_protect_utils_->GetHardwareWriteProtectionStatus(
              &hwwp_enabled) &&
          !hwwp_enabled) {
        return NextStateCaseWrapper(RmadState::StateCase::kWpDisablePhysical);
      }
      // Otherwise, let the user choose between physical method or RSU.
      return NextStateCaseWrapper(RmadState::StateCase::kWpDisableMethod);
    }
  }

  // If it's not MLB repair, proceed to select the device destination.
  return NextStateCaseWrapper(RmadState::StateCase::kDeviceDestination);
}

bool ComponentsRepairStateHandler::ApplyUserSelection(const RmadState& state) {
  if (!state.has_components_repair()) {
    LOG(ERROR) << "RmadState missing |components repair| state.";
    return false;
  }

  std::unordered_map<ComponentKey, RepairStatus> current_map =
      ConvertStateToDictionary(state_);
  const std::unordered_map<ComponentKey, RepairStatus> update_map =
      ConvertStateToDictionary(state);
  const bool mainboard_rework = state.components_repair().mainboard_rework();

  if (mainboard_rework) {
    // MLB rework. Set all the probed components to ORIGINAL.
    for (auto& [key, repair_status] : current_map) {
      if (repair_status != ComponentRepairStatus::RMAD_REPAIR_STATUS_MISSING) {
        repair_status = ComponentRepairStatus::RMAD_REPAIR_STATUS_ORIGINAL;
      }
    }
  } else {
    // Not MLB rework. Use |update_map| to update |current_map|.
    for (const auto& [key, new_repair_status] : update_map) {
      RmadComponent component = key.first;
      const std::string& identifier = key.second;
      if (current_map.count(key) == 0) {
        LOG(ERROR) << "New state contains an unknown component "
                   << RmadComponent_Name(component) << " " << identifier;
        return false;
      }
      RepairStatus prev_repair_status = current_map[key];
      if (prev_repair_status ==
              ComponentRepairStatus::RMAD_REPAIR_STATUS_MISSING &&
          new_repair_status !=
              ComponentRepairStatus::RMAD_REPAIR_STATUS_MISSING) {
        LOG(ERROR) << "New state contains repair state for unprobed component "
                   << RmadComponent_Name(component) << " " << identifier;
        return false;
      }
      if (prev_repair_status !=
              ComponentRepairStatus::RMAD_REPAIR_STATUS_MISSING &&
          new_repair_status ==
              ComponentRepairStatus::RMAD_REPAIR_STATUS_MISSING) {
        LOG(ERROR) << "New state missing repair state for component "
                   << RmadComponent_Name(component) << " " << identifier;
        return false;
      }
      current_map[key] = new_repair_status;
    }
  }
  // Check if there are any components that still has UNKNOWN repair state.
  for (const auto& [key, repair_status] : current_map) {
    if (repair_status == ComponentRepairStatus::RMAD_REPAIR_STATUS_UNKNOWN) {
      LOG(ERROR) << "Component " << RmadComponent_Name(key.first) << " "
                 << key.second << " has unknown repair state";
      return false;
    }
  }

  // Convert |current_map| back to |state_|.
  state_ = ConvertDictionaryToState(current_map, mainboard_rework);
  return true;
}

bool ComponentsRepairStateHandler::StoreVars() const {
  // Set |mlb_repair|.
  const bool mlb_repair = state_.components_repair().mainboard_rework();
  json_store_->SetValue(kMlbRepair, mlb_repair);

  // Set |replaced_components|.
  std::vector<std::string> replaced_components = GetReplacedComponents();
  json_store_->SetValue(kReplacedComponentNames, replaced_components);

  if (!RecordSelectedComponentsToLogs(json_store_, replaced_components,
                                      mlb_repair)) {
    LOG(ERROR) << "Failed to store |mlb_repair| to |json_store_|";
    return false;
  }

  if (!MetricsUtils::SetMetricsValue(
          json_store_, kMetricsMlbReplacement,
          MainboardReplacement_Name(
              mlb_repair
                  ? MainboardReplacement::RMAD_MLB_REPLACEMENT_REPLACED
                  : MainboardReplacement::RMAD_MLB_REPLACEMENT_ORIGINAL))) {
    LOG(ERROR) << "Failed to store mainboard_replacement to metrics";
    return false;
  }

  if (!mlb_repair &&
      !MetricsUtils::SetMetricsValue(json_store_, kMetricsReplacedComponents,
                                     replaced_components)) {
    LOG(ERROR) << "Failed to store replaced_components to metrics";
    return false;
  }

  return true;
}

std::vector<std::string> ComponentsRepairStateHandler::GetReplacedComponents()
    const {
  std::vector<std::string> replaced_components;
  for (auto [key, repair_status] : ConvertStateToDictionary(state_)) {
    if (repair_status == ComponentRepairStatus::RMAD_REPAIR_STATUS_REPLACED) {
      replaced_components.push_back(RmadComponent_Name(key.first));
    }
  }
  return replaced_components;
}

}  // namespace rmad
