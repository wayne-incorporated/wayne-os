// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/system/runtime_probe_client_impl.h"

#include <unordered_map>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <brillo/errors/error.h>
#include <dbus/bus.h>
#include <rmad/proto_bindings/rmad.pb.h>
#include <runtime_probe/dbus-proxies.h>

#include "rmad/utils/component_utils.h"

namespace {

const std::unordered_map<rmad::RmadComponent,
                         runtime_probe::ProbeRequest::SupportCategory>
    kRmadToRuntimeProbeComponentMap = {
        {rmad::RMAD_COMPONENT_BATTERY, runtime_probe::ProbeRequest::battery},
        {rmad::RMAD_COMPONENT_STORAGE, runtime_probe::ProbeRequest::storage},
        {rmad::RMAD_COMPONENT_VPD_CACHED,
         runtime_probe::ProbeRequest::vpd_cached},
        {rmad::RMAD_COMPONENT_NETWORK, runtime_probe::ProbeRequest::network},
        {rmad::RMAD_COMPONENT_CAMERA, runtime_probe::ProbeRequest::camera},
        {rmad::RMAD_COMPONENT_STYLUS, runtime_probe::ProbeRequest::stylus},
        {rmad::RMAD_COMPONENT_TOUCHPAD, runtime_probe::ProbeRequest::touchpad},
        {rmad::RMAD_COMPONENT_TOUCHSCREEN,
         runtime_probe::ProbeRequest::touchscreen},
        {rmad::RMAD_COMPONENT_DRAM, runtime_probe::ProbeRequest::dram},
        {rmad::RMAD_COMPONENT_DISPLAY_PANEL,
         runtime_probe::ProbeRequest::display_panel},
        {rmad::RMAD_COMPONENT_CELLULAR, runtime_probe::ProbeRequest::cellular},
        {rmad::RMAD_COMPONENT_ETHERNET, runtime_probe::ProbeRequest::ethernet},
        {rmad::RMAD_COMPONENT_WIRELESS, runtime_probe::ProbeRequest::wireless}};

template <typename T>
bool DefaultFilter(const T& component) {
  return true;
}

bool IsInternalNetwork(const runtime_probe::Network& network) {
  return network.values().bus_type() != "usb";
}

bool IsInternalCamera(const runtime_probe::Camera& camera) {
  return camera.values().usb_removable() != runtime_probe::REMOVABLE;
}

template <typename T>
void AppendComponents(rmad::RmadComponent component_type,
                      const google::protobuf::RepeatedPtrField<T>& arr,
                      bool use_customized_identifier,
                      rmad::ComponentsWithIdentifier* components,
                      bool (*filter_func)(const T&) = DefaultFilter<T>) {
  for (const T& component : arr) {
    if (filter_func(component)) {
      components->emplace_back(component_type,
                               use_customized_identifier
                                   ? rmad::GetComponentIdentifier(component)
                                   : component.name());
    }
  }
}

}  // namespace

namespace rmad {

RuntimeProbeClientImpl::RuntimeProbeClientImpl(
    const scoped_refptr<dbus::Bus>& bus) {
  runtime_probe_proxy_ =
      std::make_unique<org::chromium::RuntimeProbeProxy>(bus);
}

RuntimeProbeClientImpl::RuntimeProbeClientImpl(
    std::unique_ptr<org::chromium::RuntimeProbeProxyInterface>
        runtime_probe_proxy)
    : runtime_probe_proxy_(std::move(runtime_probe_proxy)) {}

RuntimeProbeClientImpl::~RuntimeProbeClientImpl() = default;

bool RuntimeProbeClientImpl::ProbeCategories(
    const std::vector<RmadComponent>& categories,
    bool use_customized_identifier,
    ComponentsWithIdentifier* components) {
  runtime_probe::ProbeRequest request;
  if (categories.size()) {
    request.set_probe_default_category(false);
    for (RmadComponent category : categories) {
      CHECK_NE(kRmadToRuntimeProbeComponentMap.count(category), 0);
      request.add_categories(kRmadToRuntimeProbeComponentMap.at(category));
    }
  } else {
    request.set_probe_default_category(true);
  }
  brillo::ErrorPtr error;
  runtime_probe::ProbeResult reply;
  if (!runtime_probe_proxy_->ProbeCategories(request, &reply, &error)) {
    LOG(ERROR) << "Failed to call runtime_probe D-Bus service. "
               << "code=" << error->GetCode()
               << ", message=" << error->GetMessage() << "";
    return false;
  }

  if (reply.error() != runtime_probe::RUNTIME_PROBE_ERROR_NOT_SET) {
    LOG(ERROR) << "runtime_probe returns error code " << reply.error();
    return false;
  }

  components->clear();
  AppendComponents(rmad::RMAD_COMPONENT_BATTERY, reply.battery(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_STORAGE, reply.storage(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_CAMERA, reply.camera(),
                   use_customized_identifier, components, IsInternalCamera);
  AppendComponents(rmad::RMAD_COMPONENT_STYLUS, reply.stylus(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_TOUCHPAD, reply.touchpad(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_TOUCHSCREEN, reply.touchscreen(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_DRAM, reply.dram(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_DISPLAY_PANEL, reply.display_panel(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_CELLULAR, reply.cellular(),
                   use_customized_identifier, components, IsInternalNetwork);
  AppendComponents(rmad::RMAD_COMPONENT_ETHERNET, reply.ethernet(),
                   use_customized_identifier, components, IsInternalNetwork);
  AppendComponents(rmad::RMAD_COMPONENT_WIRELESS, reply.wireless(),
                   use_customized_identifier, components, IsInternalNetwork);

  return true;
}

bool RuntimeProbeClientImpl::ProbeSsfcComponents(
    bool use_customized_identifier, ComponentsWithIdentifier* components) {
  runtime_probe::ProbeSsfcComponentsRequest request;
  brillo::ErrorPtr error;
  runtime_probe::ProbeSsfcComponentsResponse reply;
  if (!runtime_probe_proxy_->ProbeSsfcComponents(request, &reply, &error)) {
    LOG(ERROR) << "Failed to call runtime_probe D-Bus service. "
               << "code=" << error->GetCode()
               << ", message=" << error->GetMessage() << "";
    return false;
  }

  if (reply.error() != runtime_probe::RUNTIME_PROBE_ERROR_NOT_SET) {
    LOG(ERROR) << "runtime_probe returns error code " << reply.error();
    return false;
  }

  components->clear();
  AppendComponents(rmad::RMAD_COMPONENT_AP_I2C, reply.ap_i2c(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_EC_I2C, reply.ec_i2c(),
                   use_customized_identifier, components);
  AppendComponents(rmad::RMAD_COMPONENT_TCPC, reply.tcpc(),
                   use_customized_identifier, components);

  return true;
}

}  // namespace rmad
