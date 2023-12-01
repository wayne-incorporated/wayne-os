// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/system/cryptohome_client_impl.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/bus.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

namespace rmad {

CryptohomeClientImpl::CryptohomeClientImpl(
    const scoped_refptr<dbus::Bus>& bus) {
  install_attributes_proxy_ =
      std::make_unique<org::chromium::InstallAttributesInterfaceProxy>(bus);
}

CryptohomeClientImpl::CryptohomeClientImpl(
    std::unique_ptr<org::chromium::InstallAttributesInterfaceProxyInterface>
        install_attributes_proxy)
    : install_attributes_proxy_(std::move(install_attributes_proxy)) {}

CryptohomeClientImpl::~CryptohomeClientImpl() = default;

bool CryptohomeClientImpl::IsCcdBlocked() {
  uint32_t fwmp_flags;
  if (!GetFwmp(&fwmp_flags)) {
    return false;
  }
  return (fwmp_flags &
          cryptohome::DEVELOPER_DISABLE_CASE_CLOSED_DEBUGGING_UNLOCK) != 0;
}

bool CryptohomeClientImpl::GetFwmp(uint32_t* flags) {
  user_data_auth::GetFirmwareManagementParametersRequest request;
  user_data_auth::GetFirmwareManagementParametersReply reply;

  brillo::ErrorPtr error;
  if (!install_attributes_proxy_->GetFirmwareManagementParameters(
          request, &reply, &error) ||
      error) {
    LOG(ERROR) << "Failed to call GetFirmwareManagementParameters from "
               << "cryptohome proxy";
    return false;
  }

  // This can be expected when the device doesn't have FWMP.
  if (reply.error() != user_data_auth::CRYPTOHOME_ERROR_NOT_SET) {
    VLOG(1) << "Failed to get FWMP. Error code " << reply.error();
    return false;
  }

  VLOG(1) << "Get FWMP flags: " << reply.fwmp().flags();
  if (flags) {
    *flags = reply.fwmp().flags();
  }
  return true;
}

}  // namespace rmad
