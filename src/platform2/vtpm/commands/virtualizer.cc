// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/virtualizer.h"

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <trunks/command_parser.h>
#include <trunks/response_serializer.h>
#include <trunks/tpm_generated.h>

#include "vtpm/commands/forward_command.h"
#include "vtpm/commands/get_capability_command.h"
#include "vtpm/commands/nv_read_command.h"
#include "vtpm/commands/nv_read_public_command.h"
#include "vtpm/commands/unsupported_command.h"

namespace vtpm {

namespace {

// Handles and index from "TCG TPM v2.0 Provisioning Guidance" v1r1 Table 2 and
// "TCG EK Credential Profile For TPM Family 2.0; Level 0" v2.4r3.
//
// Note that since these are ECC objects they are at different locations than
// the RSA objects.
constexpr trunks::TPM_HANDLE kSrkHandle = 0x81000002;
constexpr trunks::TPM_HANDLE kEkHandle = 0x81010002;
constexpr trunks::TPM_NV_INDEX kVekCertIndex = 0x01C0000a;

// TODO(b/228789530): Virtualizer is not the best one that decides the layout of
// files. We should make sure that the path is managed in a more systematic way,
// and it should be revolved after all the persistent data is ready, and before
// the bug is resolved.
constexpr char kVsrkCachePath[] = "/var/lib/vtpm/vsrk.blob";
constexpr char kVekCachePath[] = "/var/lib/vtpm/vek.blob";
constexpr char kVekCertCachePath[] = "/var/lib/vtpm/vek_cert.blob";
constexpr char kVirtualEndorsementPassword[] = "";

constexpr trunks::TPM_CC kSupportedForwardCommands[] = {
    trunks::TPM_CC_ReadPublic,
    trunks::TPM_CC_Create,
    trunks::TPM_CC_Load,
    trunks::TPM_CC_FlushContext,
    trunks::TPM_CC_StartAuthSession,
    trunks::TPM_CC_PolicySecret,
    trunks::TPM_CC_MakeCredential,
    trunks::TPM_CC_ActivateCredential,
    trunks::TPM_CC_Hash,
    trunks::TPM_CC_Sign,
    trunks::TPM_CC_VerifySignature,
    trunks::TPM_CC_Certify,
    trunks::TPM_CC_CertifyCreation,
};

}  // namespace

std::unique_ptr<Virtualizer> Virtualizer::Create(Virtualizer::Profile profile) {
  std::unique_ptr<Virtualizer> v =
      std::unique_ptr<Virtualizer>(new Virtualizer());
  if (profile == Virtualizer::Profile::kGLinux) {
    CHECK(v->trunks_factory_.Initialize())
        << " Failed to initialize trunks factory.";
    v->command_parser_ = &v->real_command_parser_;
    v->response_serializer_ = &v->real_response_serializer_;

    // Set up VSRK.
    v->vsrk_cache_ =
        std::make_unique<DiskCacheBlob>(base::FilePath(kVsrkCachePath));
    v->cacheable_vsrk_ =
        std::make_unique<CacheableBlob>(&v->vsrk_, v->vsrk_cache_.get());

    // Set up attestation client.
    scoped_refptr<dbus::Bus> bus = v->system_bus_connection_.Connect();
    CHECK(bus) << "Failed to connect to system D-Bus";
    v->attestation_proxy_ =
        std::make_unique<org::chromium::AttestationProxy>(bus);

    // Set up virtual endorsemnet.
    v->attested_virtual_endorsement_ =
        std::make_unique<AttestedVirtualEndorsement>(
            v->attestation_proxy_.get());

    // NOTE: This is not ideal due to race condition between tpm manager service
    // being up and this call, and causes unnecessary crashes as other daemons
    // have. However, the fix should not be here instead of
    // `TpmManagerClient::Initialize()`.
    CHECK(tpm_manager::TpmManagerUtility::GetSingleton())
        << "Failed to initialize tpm manager utility.";
    v->endorsement_password_changer_ =
        std::make_unique<EndorsementPasswordChanger>(
            tpm_manager::TpmManagerUtility::GetSingleton(),
            kVirtualEndorsementPassword);

    // Set up VEK.
    v->vek_cache_ =
        std::make_unique<DiskCacheBlob>(base::FilePath(kVekCachePath));
    v->vek_ = std::make_unique<Vek>(v->attested_virtual_endorsement_.get());
    v->cacheable_vek_ =
        std::make_unique<CacheableBlob>(v->vek_.get(), v->vek_cache_.get());

    // Set up VEK cert.
    v->vek_cert_cache_ =
        std::make_unique<DiskCacheBlob>(base::FilePath(kVekCertCachePath));
    v->vek_cert_ =
        std::make_unique<VekCert>(v->attested_virtual_endorsement_.get());
    v->cacheable_vek_cert_ = std::make_unique<CacheableBlob>(
        v->vek_cert_.get(), v->vek_cert_cache_.get());

    v->vek_cert_manager_ = std::make_unique<VekCertManager>(
        kVekCertIndex, v->cacheable_vek_cert_.get());

    v->real_tpm_handle_manager_ = std::make_unique<RealTpmHandleManager>(
        &v->trunks_factory_, v->vek_cert_manager_.get(),
        std::map<trunks::TPM_HANDLE, Blob*>{
            {kSrkHandle, v->cacheable_vsrk_.get()},
            {kEkHandle, v->cacheable_vek_.get()},
        });

    // add `GetCapabilityCommand`.
    v->commands_.emplace_back(std::make_unique<GetCapabilityCommand>(
        &v->real_command_parser_, &v->real_response_serializer_,
        &v->direct_forwarder_, v->real_tpm_handle_manager_.get(),
        &v->real_tpm_property_manager_));

    v->AddCommandSupport(trunks::TPM_CC_GetCapability,
                         v->commands_.back().get());

    // Add `NvReadCommand`.
    // Since the only nv sapce is vEK certificate, and no known potential use of
    // any other nv space, use `vek_cert_manager_` directly.
    v->commands_.emplace_back(std::make_unique<NvReadCommand>(
        &v->real_command_parser_, &v->real_response_serializer_,
        v->vek_cert_manager_.get()));

    v->AddCommandSupport(trunks::TPM_CC_NV_Read, v->commands_.back().get());

    // Add `NvReadPublicCommand`.
    v->commands_.emplace_back(std::make_unique<NvReadPublicCommand>(
        &v->real_command_parser_, &v->real_response_serializer_,
        v->vek_cert_manager_.get(), &v->real_static_analyzer_));

    v->AddCommandSupport(trunks::TPM_CC_NV_ReadPublic,
                         v->commands_.back().get());

    // Add forwarded command w/ handle translateion.
    v->commands_.emplace_back(std::make_unique<ForwardCommand>(
        &v->real_command_parser_, &v->real_response_serializer_,
        &v->real_static_analyzer_, v->real_tpm_handle_manager_.get(),
        v->endorsement_password_changer_.get(), &v->direct_forwarder_));

    for (trunks::TPM_CC cc : kSupportedForwardCommands) {
      v->AddCommandSupport(cc, v->commands_.back().get());
    }

    // Add `SelfTestCommand`.
    v->AddCommandSupport(trunks::TPM_CC_SelfTest, &v->self_test_command_);

    // Use an `UnsupportedCommand` as fallback.
    v->commands_.emplace_back(
        std::make_unique<UnsupportedCommand>(v->response_serializer_));
    v->fallback_command_ = v->commands_.back().get();
    // Others are not implemented yet.
  }
  return v;
}

void Virtualizer::AddCommandSupport(trunks::TPM_CC cc, Command* command) {
  command_table_.emplace(cc, command);
  real_tpm_property_manager_.AddCommand(cc);
}

Virtualizer::Virtualizer(trunks::CommandParser* parser,
                         trunks::ResponseSerializer* serializer,
                         std::unordered_map<trunks::TPM_CC, Command*> table,
                         Command* fallback_command)
    : command_parser_(parser),
      response_serializer_(serializer),
      command_table_(std::move(table)),
      fallback_command_(fallback_command) {}

void Virtualizer::Run(const std::string& command,
                      CommandResponseCallback callback) {
  std::string buffer = command;
  trunks::TPMI_ST_COMMAND_TAG tag;
  trunks::UINT32 size;
  trunks::TPM_CC cc;
  const trunks::TPM_RC rc =
      command_parser_->ParseHeader(&buffer, &tag, &size, &cc);

  if (rc) {
    std::string response;
    response_serializer_->SerializeHeaderOnlyResponse(rc, &response);
    std::move(callback).Run(response);
    return;
  }

  if (command_table_.count(cc) == 0) {
    fallback_command_->Run(command, std::move(callback));
    return;
  }

  command_table_[cc]->Run(command, std::move(callback));
}

}  // namespace vtpm
