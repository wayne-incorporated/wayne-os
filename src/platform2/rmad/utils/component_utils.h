// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_COMPONENT_UTILS_H_
#define RMAD_UTILS_COMPONENT_UTILS_H_

#include <string>

#include <runtime_probe/proto_bindings/runtime_probe.pb.h>

namespace rmad {

// Identifier for each component fields.
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Battery_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Storage_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Camera_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::InputDevice_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Memory_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Edid_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Network_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::ApI2c_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::EcI2c_Fields& fields);
std::string GetComponentFieldsIdentifier(
    const runtime_probe::Tcpc_Fields& fields);

// Extension for |runtime_probe::ComponentFields|.
std::string GetComponentFieldsIdentifier(
    const runtime_probe::ComponentFields& fields);

// Extension for runtime_probe components.
template <typename Component>
std::string GetComponentIdentifier(const Component& component) {
  return GetComponentFieldsIdentifier(component.values());
}

}  // namespace rmad

#endif  // RMAD_UTILS_COMPONENT_UTILS_H_
