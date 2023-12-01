// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/error/tpm_manager_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<ScopedTssContext> TssHelper::GetScopedTssContext() {
  ScopedTssContext local_context_handle(overalls_);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Context_Create(
                      local_context_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_Create");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Context_Connect(
                      local_context_handle, nullptr)))
      .WithStatus<TPMError>("Failed to call Ospi_Context_Connect");

  return local_context_handle;
}

StatusOr<TSS_HCONTEXT> TssHelper::GetTssContext() {
  if (tss_context_.has_value()) {
    return tss_context_.value().value();
  }

  ASSIGN_OR_RETURN(ScopedTssContext context, GetScopedTssContext(),
                   _.WithStatus<TPMError>("Failed to get scoped TSS context"));

  tss_context_ = std::move(context);
  return tss_context_.value().value();
}

StatusOr<TSS_HTPM> TssHelper::GetUserTpmHandle() {
  if (user_tpm_handle_.has_value()) {
    return user_tpm_handle_.value().value();
  }

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, GetTssContext(),
                   _.WithStatus<TPMError>("Failed to get TSS context"));

  ScopedTssObject<TSS_HTPM> local_tpm_handle(overalls_, context);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Context_GetTpmObject(
                      context, local_tpm_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_GetTpmObject");

  user_tpm_handle_ = std::move(local_tpm_handle);
  return user_tpm_handle_.value().value();
}

StatusOr<ScopedTssObject<TSS_HTPM>> TssHelper::GetDelegateTpmHandle() {
  tpm_manager::GetTpmStatusRequest request;
  tpm_manager::GetTpmStatusReply reply;

  if (brillo::ErrorPtr err; !tpm_manager_.GetTpmStatus(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMManagerError>(reply.status()));

  if (reply.local_data().owner_delegate().blob().empty() ||
      reply.local_data().owner_delegate().secret().empty()) {
    return MakeStatus<TPMError>("No valid owner delegate",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, GetTssContext(),
                   _.WithStatus<TPMError>("Failed to get TSS context"));

  ScopedTssObject<TSS_HTPM> local_tpm_handle(overalls_, context);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Context_GetTpmObject(
                      context, local_tpm_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_GetTpmObject");

  TSS_HPOLICY tpm_usage_policy;
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetPolicyObject(
                      local_tpm_handle, TSS_POLICY_USAGE, &tpm_usage_policy)))
      .WithStatus<TPMError>("Failed to call Ospi_GetPolicyObject");

  brillo::Blob delegate_secret =
      brillo::BlobFromString(reply.local_data().owner_delegate().secret());
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Policy_SetSecret(
                      tpm_usage_policy, TSS_SECRET_MODE_PLAIN,
                      delegate_secret.size(), delegate_secret.data())))
      .WithStatus<TPMError>("Failed to call Ospi_Policy_SetSecret");

  brillo::Blob delegate_blob =
      brillo::BlobFromString(reply.local_data().owner_delegate().blob());
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
                      tpm_usage_policy, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
                      TSS_TSPATTRIB_POLDEL_OWNERBLOB, delegate_blob.size(),
                      delegate_blob.data())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");

  return local_tpm_handle;
}

}  // namespace hwsec
