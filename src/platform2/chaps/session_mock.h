// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SESSION_MOCK_H_
#define CHAPS_SESSION_MOCK_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/attributes.h"
#include "chaps/session.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

class SessionMock : public Session {
 public:
  SessionMock();
  SessionMock(const SessionMock&) = delete;
  SessionMock& operator=(const SessionMock&) = delete;

  ~SessionMock() override;

  MOCK_CONST_METHOD0(GetSlot, int());
  MOCK_CONST_METHOD0(GetState, CK_STATE());
  MOCK_CONST_METHOD0(IsReadOnly, bool());
  MOCK_CONST_METHOD1(IsOperationActive, bool(OperationType));
  MOCK_METHOD3(CreateObject, CK_RV(const CK_ATTRIBUTE_PTR, int, int*));
  MOCK_METHOD4(CopyObject, CK_RV(const CK_ATTRIBUTE_PTR, int, int, int*));
  MOCK_METHOD1(DestroyObject, CK_RV(int));
  MOCK_METHOD2(GetObject, bool(int, const Object**));
  MOCK_METHOD2(GetModifiableObject, bool(int, Object**));
  MOCK_METHOD1(FlushModifiableObject, CK_RV(Object*));
  MOCK_METHOD2(FindObjectsInit, CK_RV(const CK_ATTRIBUTE_PTR, int));
  MOCK_METHOD2(FindObjects, CK_RV(int, std::vector<int>*));
  MOCK_METHOD0(FindObjectsFinal, CK_RV());
  MOCK_METHOD4(OperationInit,
               CK_RV(OperationType,
                     CK_MECHANISM_TYPE,
                     const std::string&,
                     const Object*));
  MOCK_METHOD4(OperationUpdate,
               CK_RV(OperationType, const std::string&, int*, std::string*));
  MOCK_METHOD3(OperationFinal, CK_RV(OperationType, int*, std::string*));
  MOCK_METHOD1(OperationCancel, void(OperationType));
  MOCK_METHOD1(VerifyFinal, CK_RV(const std::string&));
  MOCK_METHOD4(OperationSinglePart,
               CK_RV(OperationType, const std::string&, int*, std::string*));
  MOCK_METHOD5(GenerateKey,
               CK_RV(CK_MECHANISM_TYPE,
                     const std::string&,
                     const CK_ATTRIBUTE_PTR,
                     int,
                     int*));
  MOCK_METHOD8(GenerateKeyPair,
               CK_RV(CK_MECHANISM_TYPE,
                     const std::string&,
                     const CK_ATTRIBUTE_PTR,
                     int,
                     const CK_ATTRIBUTE_PTR,
                     int,
                     int*,
                     int*));
  MOCK_METHOD1(SeedRandom, CK_RV(const std::string&));
  MOCK_METHOD2(GenerateRandom, CK_RV(int, std::string*));
  MOCK_METHOD0(IsPrivateLoaded, bool());
};

}  // namespace chaps

#endif  // CHAPS_SESSION_MOCK_H_
