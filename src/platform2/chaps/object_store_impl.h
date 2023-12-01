// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_STORE_IMPL_H_
#define CHAPS_OBJECT_STORE_IMPL_H_

#include "chaps/object_store.h"

#include <map>
#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest_prod.h>
#include <leveldb/db.h>
#include <leveldb/env.h>

#include "chaps/chaps_metrics.h"

namespace chaps {

// An ObjectStore implementation based on SQLite.
class ObjectStoreImpl : public ObjectStore {
 public:
  ObjectStoreImpl();
  ObjectStoreImpl(const ObjectStoreImpl&) = delete;
  ObjectStoreImpl& operator=(const ObjectStoreImpl&) = delete;

  ~ObjectStoreImpl() override;

  // Initializes the object store with the given database path.
  bool Init(const base::FilePath& database_path, ChapsMetrics* chaps_metrics);

  // ObjectStore methods.
  bool GetInternalBlob(int blob_id, std::string* blob) override;
  bool SetInternalBlob(int blob_id, const std::string& blob) override;
  bool SetEncryptionKey(const brillo::SecureBlob& key) override;
  bool InsertObjectBlob(const ObjectBlob& blob, int* handle) override;
  bool DeleteObjectBlob(int handle) override;
  bool DeleteAllObjectBlobs() override;
  bool UpdateObjectBlob(int handle, const ObjectBlob& blob) override;
  bool LoadPublicObjectBlobs(std::map<int, ObjectBlob>* blobs) override;
  bool LoadPrivateObjectBlobs(std::map<int, ObjectBlob>* blobs) override;

 private:
  enum BlobType { kInternal, kPrivate, kPublic };

  // Loads all object of a given type.
  bool LoadObjectBlobs(BlobType type, std::map<int, ObjectBlob>* blobs);

  // Encrypts an object blob with a random IV and appends an HMAC.
  bool Encrypt(const ObjectBlob& plain_text, ObjectBlob* cipher_text);

  // Verifies and decrypts an object blob.
  bool Decrypt(const ObjectBlob& cipher_text, ObjectBlob* plain_text);

  // Computes an HMAC and appends it to the given input.
  std::string AppendHMAC(const std::string& input,
                         const brillo::SecureBlob& key);

  // Verifies an appended HMAC and strips it from the given input.
  bool VerifyAndStripHMAC(const std::string& input,
                          const brillo::SecureBlob& key,
                          std::string* stripped);

  // Creates and returns a unique database key for a blob.
  std::string CreateBlobKey(BlobType type, int blob_id);

  // Given a valid blob key (as created by CreateBlobKey), determines whether
  // the blob is internal, public, or private and the blob id. Returns true on
  // success.
  bool ParseBlobKey(const std::string& key, BlobType* type, int* blob_id);

  // Computes and returns the next (unused) blob id;
  bool GetNextID(int* next_id);

  // Reads a blob from the database. Returns true on success.
  bool ReadBlob(const std::string& key, std::string* value);

  // Reads an integer from the database. Returns true on success.
  bool ReadInt(const std::string& key, int* value);

  // Writes a blob to the database. Returns true on success.
  bool WriteBlob(const std::string& key, const std::string& value);

  // Writes an integer to the database. Returns true on success.
  bool WriteInt(const std::string& key, int value);

  // Returns the blob type for the specified blob. If 'blob_id' is unknown,
  // kInternal is returned.
  BlobType GetBlobType(int blob_id);

  // These strings are used to construct database keys for blobs. In general the
  // format of a blob database key is: <prefix><separator><id>.
  static const char kInternalBlobKeyPrefix[];
  static const char kPublicBlobKeyPrefix[];
  static const char kPrivateBlobKeyPrefix[];
  static const char kBlobKeySeparator[];
  // The key for the database version. The existence of this value indicates the
  // database is not new.
  static const char kDatabaseVersionKey[];
  // The database key for the ID tracker, which always holds a value larger than
  // any object blob ID in use.
  static const char kIDTrackerKey[];
  static const int kAESKeySizeBytes;
  static const int kHMACSizeBytes;
  // The leveldb directory.
  static const char kDatabaseDirectory[];
  // A directory in which to backup a corrupted database before recreating.
  static const char kCorruptDatabaseDirectory[];
  // An obfuscation key used for public objects.
  static const char kObfuscationKey[];
  // The current blob format version.
  static const int kBlobVersion;

  brillo::SecureBlob key_;
  std::unique_ptr<leveldb::Env> env_;
  std::unique_ptr<leveldb::DB> db_;
  std::map<int, BlobType> blob_type_map_;
  base::FilePath database_name_;

  friend class TestObjectStoreEncryption;
  FRIEND_TEST(TestObjectStoreEncryption, EncryptionInit);
  FRIEND_TEST(TestObjectStoreEncryption, Encryption);
  FRIEND_TEST(TestObjectStoreEncryption, CBCMode);
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_STORE_IMPL_H_
