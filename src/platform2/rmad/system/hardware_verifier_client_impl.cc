// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/system/hardware_verifier_client_impl.h"

#include <memory>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/strings/stringprintf.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/hardware_verifier/dbus-constants.h>
#include <hardware_verifier/hardware_verifier.pb.h>

#include "rmad/utils/component_utils.h"

namespace rmad {

HardwareVerifierClientImpl::HardwareVerifierClientImpl(
    const scoped_refptr<dbus::Bus>& bus) {
  proxy_ = bus->GetObjectProxy(
      hardware_verifier::kHardwareVerifierServiceName,
      dbus::ObjectPath(hardware_verifier::kHardwareVerifierServicePath));
}

bool HardwareVerifierClientImpl::GetHardwareVerificationResult(
    bool* is_compliant, std::vector<std::string>* error_strings) const {
  dbus::MethodCall method_call(
      hardware_verifier::kHardwareVerifierInterfaceName,
      hardware_verifier::kVerifyComponentsMethod);

  std::unique_ptr<dbus::Response> response = proxy_->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!response.get()) {
    LOG(ERROR) << "Failed to call hardware_verifier D-Bus service";
    return false;
  }

  hardware_verifier::VerifyComponentsReply reply;
  dbus::MessageReader reader(response.get());
  if (!reader.PopArrayOfBytesAsProto(&reply)) {
    LOG(ERROR) << "Failed to decode hardware_verifier protobuf response";
    return false;
  }
  if (reply.error() != hardware_verifier::ERROR_OK) {
    LOG(ERROR) << "hardware_verifier returns error code " << reply.error();
    return false;
  }

  const hardware_verifier::HwVerificationReport& report =
      reply.hw_verification_report();
  *is_compliant = report.is_compliant();
  error_strings->clear();
  for (int i = 0; i < report.found_component_infos_size(); ++i) {
    const hardware_verifier::ComponentInfo& info =
        report.found_component_infos(i);
    if (info.qualification_status() == hardware_verifier::UNQUALIFIED ||
        info.qualification_status() == hardware_verifier::REJECTED ||
        info.qualification_status() == hardware_verifier::NO_MATCH) {
      error_strings->emplace_back(base::StringPrintf(
          "Unqualified %s: %s",
          runtime_probe::ProbeRequest_SupportCategory_Name(
              info.component_category())
              .c_str(),
          GetComponentFieldsIdentifier(info.component_fields()).c_str()));
    }
  }
  return true;
}

}  // namespace rmad
