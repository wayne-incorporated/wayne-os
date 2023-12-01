// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_ATTESTATION_INTERFACE_H_
#define ATTESTATION_COMMON_ATTESTATION_INTERFACE_H_

#include <string>

#include <base/functional/callback_forward.h>

#include <attestation/proto_bindings/interface.pb.h>

namespace attestation {

// The main attestation interface implemented by proxies and services. The
// anticipated flow looks like this:
//   [APP] -> AttestationInterface -> [IPC] -> AttestationInterface
class AttestationInterface {
 public:
  virtual ~AttestationInterface() = default;

  // Performs initialization tasks that may take a long time. This method must
  // be successfully called before calling any other method. Returns true on
  // success.
  virtual bool Initialize() = 0;

  // Processes a GetFeaturesRequest and responds with a GetFeaturesReply.
  using GetFeaturesCallback = base::OnceCallback<void(const GetFeaturesReply&)>;
  virtual void GetFeatures(const GetFeaturesRequest& request,
                           GetFeaturesCallback callback) = 0;

  // Processes a GetKeyInfoRequest and responds with a GetKeyInfoReply.
  using GetKeyInfoCallback = base::OnceCallback<void(const GetKeyInfoReply&)>;
  virtual void GetKeyInfo(const GetKeyInfoRequest& request,
                          GetKeyInfoCallback callback) = 0;

  // Processes a GetEndorsementInfoRequest and responds with a
  // GetEndorsementInfoReply.
  using GetEndorsementInfoCallback =
      base::OnceCallback<void(const GetEndorsementInfoReply&)>;
  virtual void GetEndorsementInfo(const GetEndorsementInfoRequest& request,
                                  GetEndorsementInfoCallback callback) = 0;

  // Processes a GetAttestationKeyInfoRequest and responds with a
  // GetAttestationKeyInfoReply.
  using GetAttestationKeyInfoCallback =
      base::OnceCallback<void(const GetAttestationKeyInfoReply&)>;
  virtual void GetAttestationKeyInfo(
      const GetAttestationKeyInfoRequest& request,
      GetAttestationKeyInfoCallback callback) = 0;

  // Processes a ActivateAttestationKeyRequest and responds with a
  // ActivateAttestationKeyReply.
  using ActivateAttestationKeyCallback =
      base::OnceCallback<void(const ActivateAttestationKeyReply&)>;
  virtual void ActivateAttestationKey(
      const ActivateAttestationKeyRequest& request,
      ActivateAttestationKeyCallback callback) = 0;

  // Processes a CreateCertifiableKeyRequest and responds with a
  // CreateCertifiableKeyReply.
  using CreateCertifiableKeyCallback =
      base::OnceCallback<void(const CreateCertifiableKeyReply&)>;
  virtual void CreateCertifiableKey(const CreateCertifiableKeyRequest& request,
                                    CreateCertifiableKeyCallback callback) = 0;

  // Processes a DecryptRequest and responds with a DecryptReply.
  using DecryptCallback = base::OnceCallback<void(const DecryptReply&)>;
  virtual void Decrypt(const DecryptRequest& request,
                       DecryptCallback callback) = 0;

  // Processes a SignRequest and responds with a SignReply.
  using SignCallback = base::OnceCallback<void(const SignReply&)>;
  virtual void Sign(const SignRequest& request, SignCallback callback) = 0;

  // Processes a RegisterKeyWithChapsTokenRequest and responds with a
  // RegisterKeyWithChapsTokenReply.
  using RegisterKeyWithChapsTokenCallback =
      base::OnceCallback<void(const RegisterKeyWithChapsTokenReply&)>;
  virtual void RegisterKeyWithChapsToken(
      const RegisterKeyWithChapsTokenRequest& request,
      RegisterKeyWithChapsTokenCallback callback) = 0;

  // Processes a GetEnrollmentPreparationsRequest and responds with a
  // GetEnrollmentPreparationsReply.
  using GetEnrollmentPreparationsCallback =
      base::OnceCallback<void(const GetEnrollmentPreparationsReply&)>;
  virtual void GetEnrollmentPreparations(
      const GetEnrollmentPreparationsRequest& request,
      GetEnrollmentPreparationsCallback callback) = 0;

  // Processes a GetStatusRequest and responds with a
  // GetStatusReply.
  using GetStatusCallback = base::OnceCallback<void(const GetStatusReply&)>;
  virtual void GetStatus(const GetStatusRequest& request,
                         GetStatusCallback callback) = 0;

  // Processes a VerifyRequest and responds with a
  // VerifyReply.
  using VerifyCallback = base::OnceCallback<void(const VerifyReply&)>;
  virtual void Verify(const VerifyRequest& request,
                      VerifyCallback callback) = 0;

  // Processes a CreateEnrollRequestRequest and responds with a
  // CreateEnrollRequestReply.
  using CreateEnrollRequestCallback =
      base::OnceCallback<void(const CreateEnrollRequestReply&)>;
  virtual void CreateEnrollRequest(const CreateEnrollRequestRequest& request,
                                   CreateEnrollRequestCallback callback) = 0;

  // Processes a FinishEnrollRequest and responds with a
  // FinishEnrollReply.
  using FinishEnrollCallback =
      base::OnceCallback<void(const FinishEnrollReply&)>;
  virtual void FinishEnroll(const FinishEnrollRequest& request,
                            FinishEnrollCallback callback) = 0;

  // Processes a EnrollRequest and responds with a
  // EnrollReply.
  using EnrollCallback = base::OnceCallback<void(const EnrollReply&)>;
  virtual void Enroll(const EnrollRequest& request,
                      EnrollCallback callback) = 0;

  // Processes a CreateCertificateRequestRequest and responds with a
  // CreateCertificateRequestReply.
  using CreateCertificateRequestCallback =
      base::OnceCallback<void(const CreateCertificateRequestReply&)>;
  virtual void CreateCertificateRequest(
      const CreateCertificateRequestRequest& request,
      CreateCertificateRequestCallback callback) = 0;

  // Processes a FinishCertificateRequestRequest and responds with a
  // FinishCertificateRequestReply.
  using FinishCertificateRequestCallback =
      base::OnceCallback<void(const FinishCertificateRequestReply&)>;
  virtual void FinishCertificateRequest(
      const FinishCertificateRequestRequest& request,
      FinishCertificateRequestCallback callback) = 0;

  // Processes a GetCertificateRequest and responds with a
  // GetCertificateReply.
  using GetCertificateCallback =
      base::OnceCallback<void(const GetCertificateReply&)>;
  virtual void GetCertificate(const GetCertificateRequest& request,
                              GetCertificateCallback callback) = 0;

  // Processes a SignEnterpriseChallengeRequest and responds with a
  // SignEnterpriseChallengeReply.
  using SignEnterpriseChallengeCallback =
      base::OnceCallback<void(const SignEnterpriseChallengeReply&)>;
  virtual void SignEnterpriseChallenge(
      const SignEnterpriseChallengeRequest& request,
      SignEnterpriseChallengeCallback callback) = 0;

  // Processes a SignSimpleChallengeRequest and responds with a
  // SignSimpleChallengeReply.
  using SignSimpleChallengeCallback =
      base::OnceCallback<void(const SignSimpleChallengeReply&)>;
  virtual void SignSimpleChallenge(const SignSimpleChallengeRequest& request,
                                   SignSimpleChallengeCallback callback) = 0;

  // Processes a SetKeyPayloadRequest and responds with a
  // SetKeyPayloadReply.
  using SetKeyPayloadCallback =
      base::OnceCallback<void(const SetKeyPayloadReply&)>;
  virtual void SetKeyPayload(const SetKeyPayloadRequest& request,
                             SetKeyPayloadCallback callback) = 0;

  // Processes a DeleteKeysRequest and responds with a
  // DeleteKeysReply.
  using DeleteKeysCallback = base::OnceCallback<void(const DeleteKeysReply&)>;
  virtual void DeleteKeys(const DeleteKeysRequest& request,
                          DeleteKeysCallback callback) = 0;

  // Processes a ResetIdentityRequest and responds with a
  // ResetIdentityReply.
  using ResetIdentityCallback =
      base::OnceCallback<void(const ResetIdentityReply&)>;
  virtual void ResetIdentity(const ResetIdentityRequest& request,
                             ResetIdentityCallback callback) = 0;

  // Processes a GetEnrollmentId request and responds with GetEnrollmentIdReply.
  using GetEnrollmentIdCallback =
      base::OnceCallback<void(const GetEnrollmentIdReply&)>;
  virtual void GetEnrollmentId(const GetEnrollmentIdRequest& request,
                               GetEnrollmentIdCallback callback) = 0;

  // Processes a GetCertifiedNvIndex request and responds with
  // GetCertifiedNvIndexReply.
  using GetCertifiedNvIndexCallback =
      base::OnceCallback<void(const GetCertifiedNvIndexReply&)>;
  virtual void GetCertifiedNvIndex(const GetCertifiedNvIndexRequest& request,
                                   GetCertifiedNvIndexCallback callback) = 0;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_ATTESTATION_INTERFACE_H_
