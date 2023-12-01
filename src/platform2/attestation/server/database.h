// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_DATABASE_H_
#define ATTESTATION_SERVER_DATABASE_H_

#include "attestation/common/database.pb.h"

namespace attestation {

// Manages a persistent database of attestation-related data.
class Database {
 public:
  virtual ~Database() = default;

  // Const access to the database protobuf.
  virtual const AttestationDatabase& GetProtobuf() const = 0;

  // Mutable access to the database protobuf. Changes made to the protobuf will
  // be reflected immediately by GetProtobuf() but will not be persisted to disk
  // until SaveChanges is called successfully.
  virtual AttestationDatabase* GetMutableProtobuf() = 0;

  // Writes the current database protobuf to disk.
  virtual bool SaveChanges() = 0;

  // Reloads the database protobuf from disk.
  virtual bool Reload() = 0;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_DATABASE_H_
