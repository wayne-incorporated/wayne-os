// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/get_capability_command.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/logging.h>
#include <trunks/command_parser.h>
#include <trunks/error_codes.h>
#include <trunks/response_serializer.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/tpm_handle_manager.h"

namespace vtpm {

namespace {

std::string CapabilityToString(trunks::TPM_CAP cap) {
  switch (cap) {
    case trunks::TPM_CAP_ALGS:
      return "TPM_CAP_ALGS";
    case trunks::TPM_CAP_HANDLES:
      return "TPM_CAP_HANDLES";
    case trunks::TPM_CAP_COMMANDS:
      return "TPM_CAP_COMMANDS";
    case trunks::TPM_CAP_PP_COMMANDS:
      return "TPM_CAP_PP_COMMANDS";
    case trunks::TPM_CAP_AUDIT_COMMANDS:
      return "TPM_CAP_AUDIT_COMMANDS";
    case trunks::TPM_CAP_PCRS:
      return "TPM_CAP_PCRS";
    case trunks::TPM_CAP_TPM_PROPERTIES:
      return "TPM_CAP_TPM_PROPERTIES";
    case trunks::TPM_CAP_PCR_PROPERTIES:
      return "TPM_CAP_PCR_PROPERTIES";
    case trunks::TPM_CAP_ECC_CURVES:
      return "TPM_CAP_ECC_CURVES";
    case trunks::TPM_CAP_VENDOR_PROPERTY:
      return "TPM_CAP_VENDOR_PROPERTY";
    default:
      LOG(DFATAL) << __func__ << " only supports defined TPM-CAP; got: " << cap;
      return "(Unknown TPM_CAP)";
  }
}

}  // namespace

GetCapabilityCommand::GetCapabilityCommand(
    trunks::CommandParser* command_parser,
    trunks::ResponseSerializer* response_serializer,
    Command* direct_forwarder,
    TpmHandleManager* tpm_handle_manager,
    TpmPropertyManager* tpm_property_manager)
    : command_parser_(command_parser),
      response_serializer_(response_serializer),
      direct_forwarder_(direct_forwarder),
      tpm_handle_manager_(tpm_handle_manager),
      tpm_property_manager_(tpm_property_manager) {
  CHECK(command_parser_);
  CHECK(response_serializer_);
  CHECK(direct_forwarder_);
  CHECK(tpm_handle_manager_);
  CHECK(tpm_property_manager_);
}

void GetCapabilityCommand::Run(const std::string& command,
                               CommandResponseCallback callback) {
  trunks::TPM_CAP cap;
  trunks::UINT32 property;
  trunks::UINT32 property_count;
  std::string buffer = command;
  trunks::TPM_RC rc = command_parser_->ParseCommandGetCapability(
      &buffer, &cap, &property, &property_count);
  if (rc) {
    ReturnWithError(rc, std::move(callback));
    return;
  }

  // If the capability is not defined by TPM2.0 spec, return error.
  if ((cap < trunks::TPM_CAP_FIRST || cap > trunks::TPM_CAP_LAST) &&
      cap != trunks::TPM_CAP_VENDOR_PROPERTY) {
    LOG(ERROR) << __func__ << ": Unexpected capability: " << cap;
    ReturnWithError(trunks::TPM_RC_VALUE, std::move(callback));
    return;
  }

  trunks::TPMI_YES_NO has_more = NO;
  trunks::TPMS_CAPABILITY_DATA cap_data = {.capability = cap};

  switch (cap) {
    // The implementation of the algorithms are backed by the host TPM.
    case trunks::TPM_CAP_ALGS:
      return direct_forwarder_->Run(command, std::move(callback));
    case trunks::TPM_CAP_HANDLES:
      rc = GetCapabilityTpmHandles(property, property_count, has_more,
                                   cap_data.data.handles);
      break;
    case trunks::TPM_CAP_COMMANDS:
      rc = GetCapabilityCommands(property, property_count, has_more,
                                 cap_data.data.command);
      break;
    case trunks::TPM_CAP_PCRS:
      rc = GetCapabilityPCRs(property, property_count, has_more,
                             cap_data.data.assigned_pcr);
      break;
    case trunks::TPM_CAP_TPM_PROPERTIES:
      rc = GetCapabilityTpmProperties(property, property_count, has_more,
                                      cap_data.data.tpm_properties);
      break;
    default:
      LOG(ERROR) << __func__
                 << ": Unimplemented capability: " << CapabilityToString(cap);
      rc = trunks::TPM_RC_VALUE;
      break;
  }

  if (rc) {
    ReturnWithError(rc, std::move(callback));
    return;
  }

  std::string response;
  response_serializer_->SerializeResponseGetCapability(has_more, cap_data,
                                                       &response);
  std::move(callback).Run(response);
  return;
}

trunks::TPM_RC GetCapabilityCommand::GetCapabilityTpmHandles(
    trunks::UINT32 property,
    trunks::UINT32 property_count,
    trunks::TPMI_YES_NO& has_more,
    trunks::TPML_HANDLE& handles) {
  if (!tpm_handle_manager_->IsHandleTypeSuppoerted(property)) {
    // Return empty handles if the handle type is not supporeted.
    has_more = NO;
    handles.count = 0;
    return trunks::TPM_RC_SUCCESS;
  }

  std::vector<trunks::TPM_HANDLE> found_handles;
  trunks::TPM_RC rc =
      tpm_handle_manager_->GetHandleList(property, &found_handles);
  if (rc) {
    LOG(ERROR) << __func__
               << ": Failed to get handle list: " << trunks::GetErrorString(rc);
    return rc;
  }

  if (property_count > MAX_CAP_HANDLES) {
    property_count = MAX_CAP_HANDLES;
  }

  has_more = (found_handles.size() > property_count ? YES : NO);
  handles.count = has_more ? property_count : found_handles.size();

  std::copy(found_handles.begin(), found_handles.begin() + handles.count,
            handles.handle);

  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC GetCapabilityCommand::GetCapabilityCommands(
    trunks::UINT32 property,
    trunks::UINT32 property_count,
    trunks::TPMI_YES_NO& has_more,
    trunks::TPML_CCA& commands) {
  const std::vector<trunks::TPM_CC>& command_list =
      tpm_property_manager_->GetCommandList();
  // Get the commands from the lower bound.
  auto iter =
      std::lower_bound(command_list.cbegin(), command_list.cend(), property);
  const size_t command_count = std::distance(iter, command_list.cend());
  commands.count = std::min({static_cast<size_t>(property_count), command_count,
                             std::size(commands.command_attributes)});
  has_more = (commands.count < command_count ? YES : NO);
  for (int i = 0; i < commands.count; ++i, ++iter) {
    commands.command_attributes[i] = *iter;
  }
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC GetCapabilityCommand::GetCapabilityPCRs(
    trunks::UINT32 property,
    trunks::UINT32 property_count,
    trunks::TPMI_YES_NO& has_more,
    trunks::TPML_PCR_SELECTION& assigned_pcr) {
  // we don't support PCR; just set the everything to 0.
  assigned_pcr.count = 0;
  return trunks::TPM_RC_SUCCESS;
}

trunks::TPM_RC GetCapabilityCommand::GetCapabilityTpmProperties(
    trunks::UINT32 property,
    trunks::UINT32 property_count,
    trunks::TPMI_YES_NO& has_more,
    trunks::TPML_TAGGED_TPM_PROPERTY& tpm_properties) {
  const std::vector<trunks::TPMS_TAGGED_PROPERTY>& capability_properties_list =
      tpm_property_manager_->GetCapabilityPropertyList();

  // The spec asks us to provide the first property on or after the provided
  // "property" handle.
  auto iter =
      std::lower_bound(capability_properties_list.cbegin(),
                       capability_properties_list.cend(), property,
                       [](const trunks::TPMS_TAGGED_PROPERTY& tagged_prop,
                          const trunks::UINT32& property) {
                         return tagged_prop.property < property;
                       });
  const size_t capability_properties_count =
      std::distance(iter, capability_properties_list.cend());
  tpm_properties.count = std::min({static_cast<size_t>(property_count),
                                   capability_properties_count,
                                   std::size(tpm_properties.tpm_property)});
  has_more = (tpm_properties.count < capability_properties_count ? YES : NO);
  for (int i = 0; i < tpm_properties.count; i++, ++iter) {
    tpm_properties.tpm_property[i] = *iter;
  }
  return trunks::TPM_RC_SUCCESS;
}

void GetCapabilityCommand::ReturnWithError(trunks::TPM_RC rc,
                                           CommandResponseCallback callback) {
  DCHECK_NE(rc, trunks::TPM_RC_SUCCESS);
  std::string response;
  response_serializer_->SerializeHeaderOnlyResponse(rc, &response);
  std::move(callback).Run(response);
}

}  // namespace vtpm
