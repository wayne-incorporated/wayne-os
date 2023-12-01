// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_PROXY_MOCK_H_
#define CHAPS_CHAPS_PROXY_MOCK_H_

#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <chaps/proto_bindings/ck_structs.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/chaps_interface.h"
#include "chaps/isolate.h"

namespace chaps {

// Defined in chaps.cc.
extern void EnableMockProxy(ChapsInterface* proxy,
                            brillo::SecureBlob* isolate_credential,
                            bool is_initialized);
extern void DisableMockProxy();
extern void SetRetryTimeParameters(uint32_t timeout_ms, uint32_t delay_ms);

// ChapsProxyMock is a mock of ChapsInterface.
class ChapsProxyMock : public ChapsInterface {
 public:
  explicit ChapsProxyMock(bool is_initialized)
      : isolate_credential_(
            IsolateCredentialManager::GetDefaultIsolateCredential()) {
    EnableMockProxy(this, &isolate_credential_, is_initialized);
  }
  ChapsProxyMock(const ChapsProxyMock&) = delete;
  ChapsProxyMock& operator=(const ChapsProxyMock&) = delete;

  ~ChapsProxyMock() override { DisableMockProxy(); }

  MOCK_METHOD3(GetSlotList,
               uint32_t(const brillo::SecureBlob&,
                        bool,
                        std::vector<uint64_t>*));
  MOCK_METHOD3(GetSlotInfo,
               uint32_t(const brillo::SecureBlob&, uint64_t, SlotInfo*));
  MOCK_METHOD3(GetTokenInfo,
               uint32_t(const brillo::SecureBlob&, uint64_t, TokenInfo*));
  MOCK_METHOD3(GetMechanismList,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        std::vector<uint64_t>*));
  MOCK_METHOD4(
      GetMechanismInfo,
      uint32_t(const brillo::SecureBlob&, uint64_t, uint64_t, MechanismInfo*));
  MOCK_METHOD4(InitToken,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::string*,
                        const std::vector<uint8_t>&));
  MOCK_METHOD3(InitPIN,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::string*));
  MOCK_METHOD4(SetPIN,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::string*,
                        const std::string*));
  MOCK_METHOD4(
      OpenSession,
      uint32_t(const brillo::SecureBlob&, uint64_t, uint64_t, uint64_t*));
  MOCK_METHOD2(CloseSession, uint32_t(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD2(CloseAllSessions, uint32_t(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD3(GetSessionInfo,
               uint32_t(const brillo::SecureBlob&, uint64_t, SessionInfo*));
  MOCK_METHOD3(GetOperationState,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        std::vector<uint8_t>*));
  MOCK_METHOD5(SetOperationState,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t));
  MOCK_METHOD4(Login,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::string*));
  MOCK_METHOD2(Logout, uint32_t(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD4(CreateObject,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t*));
  MOCK_METHOD5(CopyObject,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t*));
  MOCK_METHOD3(DestroyObject,
               uint32_t(const brillo::SecureBlob&, uint64_t, uint64_t));
  MOCK_METHOD4(
      GetObjectSize,
      uint32_t(const brillo::SecureBlob&, uint64_t, uint64_t, uint64_t*));
  MOCK_METHOD5(GetAttributeValue,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        std::vector<uint8_t>*));
  MOCK_METHOD4(SetAttributeValue,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD3(FindObjectsInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD4(FindObjects,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        std::vector<uint64_t>*));
  MOCK_METHOD2(FindObjectsFinal, uint32_t(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD5(EncryptInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t key_handle));
  MOCK_METHOD6(Encrypt,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(EncryptUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD5(EncryptFinal,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD2(EncryptCancel, void(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD5(DecryptInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t));
  MOCK_METHOD6(Decrypt,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(DecryptUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD5(DecryptFinal,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD2(DecryptCancel, void(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD4(DigestInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD6(Digest,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD3(DigestUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD3(DigestKey,
               uint32_t(const brillo::SecureBlob&, uint64_t, uint64_t));
  MOCK_METHOD5(DigestFinal,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD2(DigestCancel, void(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD5(SignInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t));
  MOCK_METHOD6(Sign,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD3(SignUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD5(SignFinal,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD2(SignCancel, void(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD5(SignRecoverInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t));
  MOCK_METHOD6(SignRecover,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD5(VerifyInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t));
  MOCK_METHOD4(Verify,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&));
  MOCK_METHOD3(VerifyUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD3(VerifyFinal,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD2(VerifyCancel, void(const brillo::SecureBlob&, uint64_t));
  MOCK_METHOD5(VerifyRecoverInit,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t));
  MOCK_METHOD6(VerifyRecover,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(DigestEncryptUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(DecryptDigestUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(SignEncryptUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(DecryptVerifyUpdate,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD6(GenerateKey,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        uint64_t*));
  MOCK_METHOD8(GenerateKeyPair,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        uint64_t*,
                        uint64_t*));
  MOCK_METHOD9(WrapKey,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        uint64_t,
                        uint64_t,
                        uint64_t*,
                        std::vector<uint8_t>*));
  MOCK_METHOD8(UnwrapKey,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&,
                        uint64_t*));
  MOCK_METHOD7(DeriveKey,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t,
                        const std::vector<uint8_t>&,
                        uint64_t*));
  MOCK_METHOD3(SeedRandom,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        const std::vector<uint8_t>&));
  MOCK_METHOD4(GenerateRandom,
               uint32_t(const brillo::SecureBlob&,
                        uint64_t,
                        uint64_t,
                        std::vector<uint8_t>*));

 private:
  brillo::SecureBlob isolate_credential_;
};

}  // namespace chaps

#endif  // CHAPS_CHAPS_PROXY_MOCK_H_
