// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/dbus_service.h"

#include <memory>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <dbus/attestation/dbus-constants.h>
#include <dbus/bus.h>
#include <dbus/object_path.h>

using brillo::dbus_utils::DBusMethodResponse;

namespace attestation {

DBusService::DBusService(const scoped_refptr<dbus::Bus>& bus,
                         AttestationInterface* service)
    : dbus_object_(nullptr, bus, dbus::ObjectPath(kAttestationServicePath)),
      service_(service) {}

void DBusService::Register(CompletionAction callback) {
  brillo::dbus_utils::DBusInterface* dbus_interface =
      dbus_object_.AddOrGetInterface(kAttestationInterface);

  dbus_interface->AddMethodHandler(kGetFeatures, base::Unretained(this),
                                   &DBusService::HandleGetFeatures);
  dbus_interface->AddMethodHandler(kGetKeyInfo, base::Unretained(this),
                                   &DBusService::HandleGetKeyInfo);
  dbus_interface->AddMethodHandler(kGetEndorsementInfo, base::Unretained(this),
                                   &DBusService::HandleGetEndorsementInfo);
  dbus_interface->AddMethodHandler(kGetAttestationKeyInfo,
                                   base::Unretained(this),
                                   &DBusService::HandleGetAttestationKeyInfo);
  dbus_interface->AddMethodHandler(kActivateAttestationKey,
                                   base::Unretained(this),
                                   &DBusService::HandleActivateAttestationKey);
  dbus_interface->AddMethodHandler(kCreateCertifiableKey,
                                   base::Unretained(this),
                                   &DBusService::HandleCreateCertifiableKey);
  dbus_interface->AddMethodHandler(kDecrypt, base::Unretained(this),
                                   &DBusService::HandleDecrypt);
  dbus_interface->AddMethodHandler(kSign, base::Unretained(this),
                                   &DBusService::HandleSign);
  dbus_interface->AddMethodHandler(
      kRegisterKeyWithChapsToken, base::Unretained(this),
      &DBusService::HandleRegisterKeyWithChapsToken);
  dbus_interface->AddMethodHandler(
      kGetEnrollmentPreparations, base::Unretained(this),
      &DBusService::HandleGetEnrollmentPreparations);
  dbus_interface->AddMethodHandler(kGetStatus, base::Unretained(this),
                                   &DBusService::HandleGetStatus);
  dbus_interface->AddMethodHandler(kVerify, base::Unretained(this),
                                   &DBusService::HandleVerify);
  dbus_interface->AddMethodHandler(kCreateEnrollRequest, base::Unretained(this),
                                   &DBusService::HandleCreateEnrollRequest);
  dbus_interface->AddMethodHandler(kFinishEnroll, base::Unretained(this),
                                   &DBusService::HandleFinishEnroll);
  dbus_interface->AddMethodHandler(kEnroll, base::Unretained(this),
                                   &DBusService::HandleEnroll);
  dbus_interface->AddMethodHandler(
      kCreateCertificateRequest, base::Unretained(this),
      &DBusService::HandleCreateCertificateRequest);
  dbus_interface->AddMethodHandler(
      kFinishCertificateRequest, base::Unretained(this),
      &DBusService::HandleFinishCertificateRequest);
  dbus_interface->AddMethodHandler(kGetCertificate, base::Unretained(this),
                                   &DBusService::HandleGetCertificate);
  dbus_interface->AddMethodHandler(kSignEnterpriseChallenge,
                                   base::Unretained(this),
                                   &DBusService::HandleSignEnterpriseChallenge);
  dbus_interface->AddMethodHandler(kSignSimpleChallenge, base::Unretained(this),
                                   &DBusService::HandleSignSimpleChallenge);
  dbus_interface->AddMethodHandler(kSetKeyPayload, base::Unretained(this),
                                   &DBusService::HandleSetKeyPayload);
  dbus_interface->AddMethodHandler(kDeleteKeys, base::Unretained(this),
                                   &DBusService::HandleDeleteKeys);
  dbus_interface->AddMethodHandler(kResetIdentity, base::Unretained(this),
                                   &DBusService::HandleResetIdentity);
  dbus_interface->AddMethodHandler(kGetEnrollmentId, base::Unretained(this),
                                   &DBusService::HandleGetEnrollmentId);
  dbus_interface->AddMethodHandler(kGetCertifiedNvIndex, base::Unretained(this),
                                   &DBusService::HandleGetCertifiedNvIndex);

  dbus_object_.RegisterAsync(std::move(callback));
}

void DBusService::HandleGetFeatures(
    std::unique_ptr<DBusMethodResponse<const GetFeaturesReply&>> response,
    const GetFeaturesRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetFeaturesReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetFeaturesReply& reply) {
    response->Return(reply);
  };
  service_->GetFeatures(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetKeyInfo(
    std::unique_ptr<DBusMethodResponse<const GetKeyInfoReply&>> response,
    const GetKeyInfoRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetKeyInfoReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetKeyInfoReply& reply) { response->Return(reply); };
  service_->GetKeyInfo(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetEndorsementInfo(
    std::unique_ptr<DBusMethodResponse<const GetEndorsementInfoReply&>>
        response,
    const GetEndorsementInfoRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetEndorsementInfoReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetEndorsementInfoReply& reply) {
    response->Return(reply);
  };
  service_->GetEndorsementInfo(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetAttestationKeyInfo(
    std::unique_ptr<DBusMethodResponse<const GetAttestationKeyInfoReply&>>
        response,
    const GetAttestationKeyInfoRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetAttestationKeyInfoReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetAttestationKeyInfoReply& reply) {
    response->Return(reply);
  };
  service_->GetAttestationKeyInfo(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleActivateAttestationKey(
    std::unique_ptr<DBusMethodResponse<const ActivateAttestationKeyReply&>>
        response,
    const ActivateAttestationKeyRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const ActivateAttestationKeyReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const ActivateAttestationKeyReply& reply) {
    response->Return(reply);
  };
  service_->ActivateAttestationKey(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleCreateCertifiableKey(
    std::unique_ptr<DBusMethodResponse<const CreateCertifiableKeyReply&>>
        response,
    const CreateCertifiableKeyRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const CreateCertifiableKeyReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const CreateCertifiableKeyReply& reply) {
    response->Return(reply);
  };
  service_->CreateCertifiableKey(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleDecrypt(
    std::unique_ptr<DBusMethodResponse<const DecryptReply&>> response,
    const DecryptRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const DecryptReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const DecryptReply& reply) { response->Return(reply); };
  service_->Decrypt(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleSign(
    std::unique_ptr<DBusMethodResponse<const SignReply&>> response,
    const SignRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const SignReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const SignReply& reply) { response->Return(reply); };
  service_->Sign(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleRegisterKeyWithChapsToken(
    std::unique_ptr<DBusMethodResponse<const RegisterKeyWithChapsTokenReply&>>
        response,
    const RegisterKeyWithChapsTokenRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer = std::shared_ptr<
      DBusMethodResponse<const RegisterKeyWithChapsTokenReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const RegisterKeyWithChapsTokenReply& reply) {
    response->Return(reply);
  };
  service_->RegisterKeyWithChapsToken(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetEnrollmentPreparations(
    std::unique_ptr<DBusMethodResponse<const GetEnrollmentPreparationsReply&>>
        response,
    const GetEnrollmentPreparationsRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer = std::shared_ptr<
      DBusMethodResponse<const GetEnrollmentPreparationsReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetEnrollmentPreparationsReply& reply) {
    response->Return(reply);
  };
  service_->GetEnrollmentPreparations(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetStatus(
    std::unique_ptr<DBusMethodResponse<const GetStatusReply&>> response,
    const GetStatusRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetStatusReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetStatusReply& reply) { response->Return(reply); };
  service_->GetStatus(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleVerify(
    std::unique_ptr<DBusMethodResponse<const VerifyReply&>> response,
    const VerifyRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const VerifyReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const VerifyReply& reply) { response->Return(reply); };
  service_->Verify(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleCreateEnrollRequest(
    std::unique_ptr<DBusMethodResponse<const CreateEnrollRequestReply&>>
        response,
    const CreateEnrollRequestRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const CreateEnrollRequestReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const CreateEnrollRequestReply& reply) {
    response->Return(reply);
  };
  service_->CreateEnrollRequest(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleFinishEnroll(
    std::unique_ptr<DBusMethodResponse<const FinishEnrollReply&>> response,
    const FinishEnrollRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const FinishEnrollReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const FinishEnrollReply& reply) {
    response->Return(reply);
  };
  service_->FinishEnroll(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleEnroll(
    std::unique_ptr<DBusMethodResponse<const EnrollReply&>> response,
    const EnrollRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const EnrollReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const EnrollReply& reply) { response->Return(reply); };
  service_->Enroll(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleCreateCertificateRequest(
    std::unique_ptr<DBusMethodResponse<const CreateCertificateRequestReply&>>
        response,
    const CreateCertificateRequestRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const CreateCertificateRequestReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const CreateCertificateRequestReply& reply) {
    response->Return(reply);
  };
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleFinishCertificateRequest(
    std::unique_ptr<DBusMethodResponse<const FinishCertificateRequestReply&>>
        response,
    const FinishCertificateRequestRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const FinishCertificateRequestReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const FinishCertificateRequestReply& reply) {
    response->Return(reply);
  };
  service_->FinishCertificateRequest(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetCertificate(
    std::unique_ptr<DBusMethodResponse<const GetCertificateReply&>> response,
    const GetCertificateRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetCertificateReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetCertificateReply& reply) {
    response->Return(reply);
  };
  service_->GetCertificate(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleSignEnterpriseChallenge(
    std::unique_ptr<DBusMethodResponse<const SignEnterpriseChallengeReply&>>
        response,
    const SignEnterpriseChallengeRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const SignEnterpriseChallengeReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const SignEnterpriseChallengeReply& reply) {
    response->Return(reply);
  };
  service_->SignEnterpriseChallenge(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleSignSimpleChallenge(
    std::unique_ptr<DBusMethodResponse<const SignSimpleChallengeReply&>>
        response,
    const SignSimpleChallengeRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const SignSimpleChallengeReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const SignSimpleChallengeReply& reply) {
    response->Return(reply);
  };
  service_->SignSimpleChallenge(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleSetKeyPayload(
    std::unique_ptr<DBusMethodResponse<const SetKeyPayloadReply&>> response,
    const SetKeyPayloadRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const SetKeyPayloadReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const SetKeyPayloadReply& reply) {
    response->Return(reply);
  };
  service_->SetKeyPayload(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleDeleteKeys(
    std::unique_ptr<DBusMethodResponse<const DeleteKeysReply&>> response,
    const DeleteKeysRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const DeleteKeysReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const DeleteKeysReply& reply) { response->Return(reply); };
  service_->DeleteKeys(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleResetIdentity(
    std::unique_ptr<DBusMethodResponse<const ResetIdentityReply&>> response,
    const ResetIdentityRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const ResetIdentityReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const ResetIdentityReply& reply) {
    response->Return(reply);
  };
  service_->ResetIdentity(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetEnrollmentId(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        const GetEnrollmentIdReply&>> response,
    const GetEnrollmentIdRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetEnrollmentIdReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetEnrollmentIdReply& reply) {
    response->Return(reply);
  };
  service_->GetEnrollmentId(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

void DBusService::HandleGetCertifiedNvIndex(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        const GetCertifiedNvIndexReply&>> response,
    const GetCertifiedNvIndexRequest& request) {
  VLOG(1) << __func__;
  // Convert |response| to a shared_ptr so |service_| can safely copy the
  // callback.
  using SharedResponsePointer =
      std::shared_ptr<DBusMethodResponse<const GetCertifiedNvIndexReply&>>;
  // A callback that fills the reply protobuf and sends it.
  auto callback = [](const SharedResponsePointer& response,
                     const GetCertifiedNvIndexReply& reply) {
    response->Return(reply);
  };
  service_->GetCertifiedNvIndex(
      request,
      base::BindOnce(callback, SharedResponsePointer(std::move(response))));
}

}  // namespace attestation
