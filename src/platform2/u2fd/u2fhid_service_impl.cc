// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/u2fhid_service_impl.h"

#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <attestation-client/attestation/dbus-constants.h>
#include <attestation/proto_bindings/interface.pb.h>
#include <base/logging.h>
#include <metrics/metrics_library.h>
#include <session_manager/dbus-proxies.h>
#include <trunks/cr50_headers/virtual_nvmem.h>

#include "u2fd/client/u2f_corp_firmware_version.h"
#include "u2fd/client/user_state.h"
#include "u2fd/u2f_corp_processor_interface.h"

namespace u2f {

namespace {

constexpr char kDeviceName[] = "Integrated U2F";
constexpr char kKeyLabelEmk[] = "attest-ent-machine";

constexpr uint32_t kDefaultVendorId = 0x18d1;
constexpr uint32_t kDefaultProductId = 0x502c;
constexpr uint32_t kCorpVendorId = 0x18d1;
constexpr uint32_t kCorpProductId = 0x5212;

}  // namespace

U2fHidServiceImpl::U2fHidServiceImpl(
    std::unique_ptr<const hwsec::U2fVendorFrontend> u2f_frontend)
    : u2f_frontend_(std::move(u2f_frontend)) {
  CHECK(u2f_frontend_);
}

bool U2fHidServiceImpl::InitializeDBusProxies(dbus::Bus* bus) {
  attestation_proxy_ = bus->GetObjectProxy(
      attestation::kAttestationServiceName,
      dbus::ObjectPath(attestation::kAttestationServicePath));

  if (!attestation_proxy_) {
    LOG(ERROR) << "Failed to initialize attestationd DBus proxy";
    return false;
  }

  return true;
}

bool U2fHidServiceImpl::CreateU2fHid(
    bool allow_g2f_attestation,
    bool include_g2f_allowlisting_data,
    bool enable_corp_protocol,
    std::function<void()> request_user_presence,
    UserState* user_state,
    org::chromium::SessionManagerInterfaceProxy* sm_proxy,
    MetricsLibraryInterface* metrics) {
  U2fCorpFirmwareVersion fw_version;
  std::string dev_id(8, '\0');

  if (enable_corp_protocol) {
    hwsec::StatusOr<hwsec::U2fVendorFrontend::RwVersion> version =
        u2f_frontend_->GetRwVersion();
    if (!version.ok()) {
      LOG(ERROR) << "GetRwVersion failed: " << version.status() << ".";
    } else {
      fw_version = U2fCorpFirmwareVersion::FromRwVersion(*version);

      u2f_corp_processor_ = std::make_unique<U2fCorpProcessorInterface>();
      u2f_corp_processor_->Initialize(fw_version, sm_proxy, u2f_frontend_.get(),
                                      metrics, request_user_presence);
    }

    hwsec::StatusOr<brillo::Blob> cert = u2f_frontend_->GetG2fCert();
    if (!cert.ok()) {
      LOG(ERROR) << "GetG2fCert failed: " << cert.status() << ".";
    } else {
      std::optional<brillo::Blob> sn = util::ParseSerialNumberFromCert(*cert);
      if (!sn.has_value()) {
        LOG(ERROR) << "Failed to parse serial number from g2f cert.";
      } else {
        dev_id = brillo::BlobToString(util::Sha256(*sn));
      }
    }
  }

  uint32_t vendor_id = enable_corp_protocol ? kCorpVendorId : kDefaultVendorId;
  uint32_t product_id =
      enable_corp_protocol ? kCorpProductId : kDefaultProductId;

  std::unique_ptr<u2f::AllowlistingUtil> allowlisting_util;

  if (include_g2f_allowlisting_data) {
    allowlisting_util = std::make_unique<u2f::AllowlistingUtil>(
        [this](int cert_size) { return GetCertifiedG2fCert(cert_size); });
  }

  u2f_msg_handler_ = std::make_unique<u2f::U2fMessageHandler>(
      std::move(allowlisting_util), request_user_presence, user_state,
      u2f_frontend_.get(), sm_proxy, metrics, allow_g2f_attestation,
      u2f_corp_processor_.get());

  u2fhid_ = std::make_unique<u2f::U2fHid>(
      std::make_unique<u2f::UHidDevice>(vendor_id, product_id, kDeviceName,
                                        "u2fd-tpm-cr50"),
      fw_version, dev_id.substr(0, 8), u2f_msg_handler_.get(),
      u2f_corp_processor_.get());

  return u2fhid_->Init();
}

std::optional<attestation::GetCertifiedNvIndexReply>
U2fHidServiceImpl::GetCertifiedG2fCert(int g2f_cert_size) {
  if (g2f_cert_size < 1 || g2f_cert_size > VIRTUAL_NV_INDEX_G2F_CERT_SIZE) {
    LOG(ERROR)
        << "Invalid G2F cert size specified for whitelisting data request";
    return std::nullopt;
  }

  attestation::GetCertifiedNvIndexRequest request;

  request.set_nv_index(VIRTUAL_NV_INDEX_G2F_CERT);
  request.set_nv_size(g2f_cert_size);
  request.set_key_label(kKeyLabelEmk);

  brillo::ErrorPtr error;

  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallMethodAndBlock(
          attestation_proxy_, attestation::kAttestationInterface,
          attestation::kGetCertifiedNvIndex, &error, request);

  if (!dbus_response) {
    LOG(ERROR) << "Failed to retrieve certified G2F cert from attestationd";
    return std::nullopt;
  }

  attestation::GetCertifiedNvIndexReply reply;

  dbus::MessageReader reader(dbus_response.get());
  if (!reader.PopArrayOfBytesAsProto(&reply)) {
    LOG(ERROR) << "Failed to parse GetCertifiedNvIndexReply";
    return std::nullopt;
  }

  if (reply.status() != attestation::AttestationStatus::STATUS_SUCCESS) {
    LOG(ERROR) << "Call get GetCertifiedNvIndex failed, status: "
               << reply.status();
    return std::nullopt;
  }

  return reply;
}

}  // namespace u2f
