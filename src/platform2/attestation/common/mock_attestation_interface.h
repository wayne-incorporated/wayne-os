// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_MOCK_ATTESTATION_INTERFACE_H_
#define ATTESTATION_COMMON_MOCK_ATTESTATION_INTERFACE_H_

#include <string>

#include <gmock/gmock.h>

#include "attestation/common/attestation_interface.h"

namespace attestation {

class MockAttestationInterface : public AttestationInterface {
 public:
  MockAttestationInterface() = default;
  virtual ~MockAttestationInterface() = default;

  MOCK_METHOD(bool, Initialize, (), (override));
  MOCK_METHOD(void,
              GetFeatures,
              (const GetFeaturesRequest&, GetFeaturesCallback),
              (override));
  MOCK_METHOD(void,
              GetKeyInfo,
              (const GetKeyInfoRequest&, GetKeyInfoCallback),
              (override));
  MOCK_METHOD(void,
              GetEndorsementInfo,
              (const GetEndorsementInfoRequest&, GetEndorsementInfoCallback),
              (override));
  MOCK_METHOD(void,
              GetAttestationKeyInfo,
              (const GetAttestationKeyInfoRequest&,
               GetAttestationKeyInfoCallback),
              (override));
  MOCK_METHOD(void,
              ActivateAttestationKey,
              (const ActivateAttestationKeyRequest&,
               ActivateAttestationKeyCallback),
              (override));
  MOCK_METHOD(void,
              CreateCertifiableKey,
              (const CreateCertifiableKeyRequest&,
               CreateCertifiableKeyCallback),
              (override));
  MOCK_METHOD(void,
              Decrypt,
              (const DecryptRequest&, DecryptCallback),
              (override));
  MOCK_METHOD(void, Sign, (const SignRequest&, SignCallback), (override));
  MOCK_METHOD(void,
              RegisterKeyWithChapsToken,
              (const RegisterKeyWithChapsTokenRequest&,
               RegisterKeyWithChapsTokenCallback),
              (override));
  MOCK_METHOD(void,
              GetEnrollmentPreparations,
              (const GetEnrollmentPreparationsRequest&,
               GetEnrollmentPreparationsCallback),
              (override));
  MOCK_METHOD(void,
              GetStatus,
              (const GetStatusRequest&, GetStatusCallback),
              (override));
  MOCK_METHOD(void, Verify, (const VerifyRequest&, VerifyCallback), (override));
  MOCK_METHOD(void,
              CreateEnrollRequest,
              (const CreateEnrollRequestRequest&, CreateEnrollRequestCallback),
              (override));
  MOCK_METHOD(void, Enroll, (const EnrollRequest&, EnrollCallback), (override));
  MOCK_METHOD(void,
              FinishEnroll,
              (const FinishEnrollRequest&, FinishEnrollCallback),
              (override));
  MOCK_METHOD(void,
              CreateCertificateRequest,
              (const CreateCertificateRequestRequest&,
               CreateCertificateRequestCallback),
              (override));
  MOCK_METHOD(void,
              FinishCertificateRequest,
              (const FinishCertificateRequestRequest&,
               FinishCertificateRequestCallback),
              (override));
  MOCK_METHOD(void,
              GetCertificate,
              (const GetCertificateRequest&, GetCertificateCallback),
              (override));
  MOCK_METHOD(void,
              SignEnterpriseChallenge,
              (const SignEnterpriseChallengeRequest&,
               SignEnterpriseChallengeCallback),
              (override));
  MOCK_METHOD(void,
              SignSimpleChallenge,
              (const SignSimpleChallengeRequest&, SignSimpleChallengeCallback),
              (override));
  MOCK_METHOD(void,
              SetKeyPayload,
              (const SetKeyPayloadRequest&, SetKeyPayloadCallback),
              (override));
  MOCK_METHOD(void,
              DeleteKeys,
              (const DeleteKeysRequest&, DeleteKeysCallback),
              (override));
  MOCK_METHOD(void,
              ResetIdentity,
              (const ResetIdentityRequest&, ResetIdentityCallback),
              (override));
  MOCK_METHOD(void,
              GetEnrollmentId,
              (const GetEnrollmentIdRequest&, GetEnrollmentIdCallback),
              (override));
  MOCK_METHOD(void,
              GetCertifiedNvIndex,
              (const GetCertifiedNvIndexRequest&, GetCertifiedNvIndexCallback),
              (override));
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_MOCK_ATTESTATION_INTERFACE_H_
