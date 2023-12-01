// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_DATABASE_IMPL_H_
#define ATTESTATION_SERVER_DATABASE_IMPL_H_

#include "attestation/server/database.h"

#include <libhwsec/frontend/attestation/frontend.h>
#include <memory>
#include <string>

#include "attestation/common/crypto_utility.h"
#include "attestation/server/attestation_service_metrics.h"

namespace attestation {

// An I/O abstraction to help with testing.
class DatabaseIO {
 public:
  // Reads the persistent database blob.
  virtual bool Read(std::string* data) = 0;
  // Writes the persistent database blob.
  virtual bool Write(const std::string& data) = 0;
};

// An implementation of Database backed by an ordinary file. Not thread safe.
// All methods must be called on the same thread as the Initialize() call.
class DatabaseImpl : public Database, public DatabaseIO {
 public:
  // Does not take ownership of pointers.
  explicit DatabaseImpl(CryptoUtility* crypto,
                        const hwsec::AttestationFrontend* hwsec);
  ~DatabaseImpl() override;

  // Reads and decrypts any existing database on disk synchronously. Must be
  // called before calling other methods. Returns true if a database has been
  // loaded, false if a new database has been created.
  bool Initialize();

  // Database methods.
  const AttestationDatabase& GetProtobuf() const override;
  AttestationDatabase* GetMutableProtobuf() override;
  bool SaveChanges() override;
  bool Reload() override;

  // DatabaseIO methods.
  bool Read(std::string* data) override;
  bool Write(const std::string& data) override;

  // Useful for testing.
  void set_io(DatabaseIO* io) { io_ = io; }

 private:
  // Encrypts |protobuf_| into |encrypted_output|. Returns true on success.
  bool EncryptProtobuf(std::string* encrypted_output);

  // Decrypts |encrypted_input| as output by EncryptProtobuf into |protobuf_|.
  // Returns true on success.
  bool DecryptProtobuf(const std::string& encrypted_input);

  AttestationDatabase protobuf_;
  DatabaseIO* io_;
  CryptoUtility* crypto_;
  const hwsec::AttestationFrontend* hwsec_;
  AttestationServiceMetrics metrics_;
  std::string database_key_;
  std::string sealed_database_key_;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_DATABASE_IMPL_H_
