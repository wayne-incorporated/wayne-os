// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_MOCK_DATABASE_H_
#define ATTESTATION_SERVER_MOCK_DATABASE_H_

#include "attestation/server/database.h"

#include <gmock/gmock.h>

namespace attestation {

class MockDatabase : public Database {
 public:
  MockDatabase();
  ~MockDatabase() override;

  MOCK_METHOD(const AttestationDatabase&, GetProtobuf, (), (const, override));
  MOCK_METHOD(AttestationDatabase*, GetMutableProtobuf, (), (override));
  MOCK_METHOD(bool, SaveChanges, (), (override));
  MOCK_METHOD(bool, Reload, (), (override));

 private:
  AttestationDatabase fake_;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_MOCK_DATABASE_H_
