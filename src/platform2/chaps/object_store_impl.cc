// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_store_impl.h"

#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "base/files/file_enumerator.h"
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/secure_blob.h>
#include <leveldb/db.h>

#include "chaps/chaps_metrics.h"
#include "chaps/chaps_utility.h"
#include "pkcs11/cryptoki.h"

using base::FilePath;
using brillo::SecureBlob;
using std::map;
using std::string;
using std::vector;

namespace {

// Logs information about |db_dir| before opening the leveldb.
// TODO(https://crbug.com/844537): Remove or decrease log level when root cause
// of disappearing system token certificates is found.
void LogDatabaseDirectoryStats(const FilePath& db_dir) {
  if (!base::DirectoryExists(db_dir)) {
    LOG(INFO) << "leveldb " << db_dir.value() << " directory did not exist.";
    return;
  }
  base::FileEnumerator file_enumerator(db_dir, false /* recursive */,
                                       base::FileEnumerator::FILES);
  std::ostringstream db_info;
  for (base::FilePath db_file = file_enumerator.Next(); !db_file.empty();
       db_file = file_enumerator.Next()) {
    base::FileEnumerator::FileInfo db_file_info = file_enumerator.GetInfo();
    db_info << "\n  " << db_file.value() << " (" << db_file_info.GetSize()
            << " bytes, " << db_file_info.GetLastModifiedTime() << ")";
  }
  LOG(INFO) << "leveldb " << db_dir.value() << " dump:" << db_info.str();
}

// Logs information about |db|.
// TODO(https://crbug.com/844537): Remove or decrease log level when root cause
// of disappearing system token certificates is found.
void LogDatabaseStats(leveldb::DB* db) {
  std::string leveldb_stats;
  if (db->GetProperty("leveldb.stats", &leveldb_stats)) {
    LOG(INFO) << "leveldb.stats:\n" << leveldb_stats;
  } else {
    LOG(WARNING) << "Failed to retrieve leveldb.stats";
  }

  // Also log the number of objects in the database. This needs to be explicitly
  // counted in leveldb.
  int key_count = 0;
  leveldb::ReadOptions read_options;
  read_options.fill_cache = false;
  std::unique_ptr<leveldb::Iterator> it(db->NewIterator(read_options));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    ++key_count;
  }
  LOG(INFO) << "leveldb contains " << key_count << " keys.";
}

}  // namespace

namespace chaps {

const char ObjectStoreImpl::kInternalBlobKeyPrefix[] = "InternalBlob";
const char ObjectStoreImpl::kPublicBlobKeyPrefix[] = "PublicBlob";
const char ObjectStoreImpl::kPrivateBlobKeyPrefix[] = "PrivateBlob";
const char ObjectStoreImpl::kBlobKeySeparator[] = "&";
const char ObjectStoreImpl::kDatabaseVersionKey[] = "DBVersion";
const char ObjectStoreImpl::kIDTrackerKey[] = "NextBlobID";
const int ObjectStoreImpl::kAESKeySizeBytes = 32;
const int ObjectStoreImpl::kHMACSizeBytes = 64;
const char ObjectStoreImpl::kDatabaseDirectory[] = "database";
const char ObjectStoreImpl::kCorruptDatabaseDirectory[] = "database_corrupt";
const char ObjectStoreImpl::kObfuscationKey[] = {
    '\x6f', '\xaa', '\x0a', '\xb6', '\x10', '\xc0', '\xa6', '\xe4',
    '\x07', '\x8b', '\x05', '\x1c', '\xd2', '\x8b', '\xac', '\x2d',
    '\xba', '\x5e', '\x14', '\x9c', '\xae', '\x57', '\xfb', '\x04',
    '\x13', '\x92', '\xc0', '\x84', '\x2a', '\xea', '\xf6', '\xfb'};
const int ObjectStoreImpl::kBlobVersion = 1;

ObjectStoreImpl::ObjectStoreImpl() {}

ObjectStoreImpl::~ObjectStoreImpl() {
  // TODO(https://crbug.com/844537): Remove or decrease log level when root
  // cause of disappearing system token certificates is found.
  if (db_) {
    LOG(INFO) << "Closing database for " << database_name_.value();
    db_.reset();
    LogDatabaseDirectoryStats(database_name_);
  }
}

bool ObjectStoreImpl::Init(const FilePath& database_path,
                           ChapsMetrics* chaps_metrics) {
  LOG(INFO) << "Opening database in: " << database_path.value();
  chaps_metrics->ReportCrosEvent(kDatabaseOpenAttempt);
  leveldb::Options options;
  options.create_if_missing = true;
  options.paranoid_checks = true;
  FilePath database_name = database_path.Append(kDatabaseDirectory);
  database_name_ = database_name;
  // TODO(https://crbug.com/844537): Remove or decrease log level when root
  // cause of disappearing system token certificates is found.
  LogDatabaseDirectoryStats(database_name);
  leveldb::DB* db = NULL;
  leveldb::Status status =
      leveldb::DB::Open(options, database_name.value(), &db);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to open database: " << status.ToString();
    chaps_metrics->ReportCrosEvent(kDatabaseCorrupted);
    LOG(WARNING) << "Attempting to repair database.";
    status = leveldb::RepairDB(database_name.value(), leveldb::Options());
    if (status.ok())
      status = leveldb::DB::Open(options, database_name.value(), &db);
  }

  if (!status.ok()) {
    LOG(ERROR) << "Failed to repair database: " << status.ToString();
    chaps_metrics->ReportCrosEvent(kDatabaseRepairFailure);
    // We don't want to risk using a database that has been corrupted. Recreate
    // the database from scratch but save the corrupted database for diagnostic
    // purposes.
    LOG(WARNING) << "Recreating database from scratch. Moving current database "
                 << "to " << kCorruptDatabaseDirectory;
    FilePath corrupt_db_path = database_path.Append(kCorruptDatabaseDirectory);
    base::DeletePathRecursively(corrupt_db_path);
    if (!base::Move(database_name, corrupt_db_path)) {
      LOG(ERROR) << "Failed to move database." << status.ToString();
      return false;
    }
    status = leveldb::DB::Open(options, database_name.value(), &db);
  }

  if (!status.ok()) {
    LOG(ERROR) << "Failed to create new database: " << status.ToString();
    chaps_metrics->ReportCrosEvent(kDatabaseCreateFailure);
    return false;
  }

  chaps_metrics->ReportCrosEvent(kDatabaseOpenedSuccessfully);

  // TODO(https://crbug.com/844537): Remove or decrease log level when root
  // cause of disappearing system token certificates is found.
  LogDatabaseStats(db);

  db_.reset(db);
  int version = 0;
  if (!ReadInt(kDatabaseVersionKey, &version)) {
    if (!WriteInt(kIDTrackerKey, 1)) {
      LOG(ERROR) << "Failed to initialize the blob ID tracker.";
      return false;
    }
    if (!WriteInt(kDatabaseVersionKey, 1)) {
      LOG(ERROR) << "Failed to initialize the database version.";
      return false;
    }
  }
  return true;
}

bool ObjectStoreImpl::GetInternalBlob(int blob_id, string* blob) {
  if (!ReadBlob(CreateBlobKey(kInternal, blob_id), blob)) {
    // Don't log this since it happens legitimately when a blob has not yet been
    // set.
    return false;
  }
  return true;
}

bool ObjectStoreImpl::SetInternalBlob(int blob_id, const string& blob) {
  if (!WriteBlob(CreateBlobKey(kInternal, blob_id), blob)) {
    LOG(ERROR) << "Failed to write internal blob: " << blob_id;
    return false;
  }
  return true;
}

bool ObjectStoreImpl::SetEncryptionKey(const SecureBlob& key) {
  if (key.size() != static_cast<size_t>(kAESKeySizeBytes)) {
    LOG(ERROR) << "Unexpected key size: " << key.size();
    return false;
  }
  key_ = key;
  return true;
}

bool ObjectStoreImpl::InsertObjectBlob(const ObjectBlob& blob, int* handle) {
  if (blob.is_private && key_.empty()) {
    LOG(ERROR) << "The store encryption key has not been initialized.";
    return false;
  }
  if (!GetNextID(handle)) {
    LOG(ERROR) << "Failed to generate blob identifier.";
    return false;
  }
  blob_type_map_[*handle] = blob.is_private ? kPrivate : kPublic;
  return UpdateObjectBlob(*handle, blob);
}

bool ObjectStoreImpl::DeleteObjectBlob(int handle) {
  leveldb::WriteOptions options;
  options.sync = true;
  string db_key = CreateBlobKey(GetBlobType(handle), handle);
  leveldb::Status status = db_->Delete(options, db_key);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to delete blob: " << status.ToString();
    return false;
  }
  return true;
}

bool ObjectStoreImpl::DeleteAllObjectBlobs() {
  vector<string> blobs_to_delete;
  std::unique_ptr<leveldb::Iterator> it(
      db_->NewIterator(leveldb::ReadOptions()));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    BlobType type;
    int id = 0;
    if (ParseBlobKey(it->key().ToString(), &type, &id) && type != kInternal)
      blobs_to_delete.push_back(it->key().ToString());
  }
  bool deleted_all = true;
  for (size_t i = 0; i < blobs_to_delete.size(); ++i) {
    leveldb::WriteOptions options;
    options.sync = true;
    leveldb::Status status = db_->Delete(options, blobs_to_delete[i]);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to delete blob: " << status.ToString();
      deleted_all = false;
    }
  }
  return deleted_all;
}

bool ObjectStoreImpl::UpdateObjectBlob(int handle, const ObjectBlob& blob) {
  ObjectBlob encrypted_blob;
  BlobType type = GetBlobType(handle);
  if (blob.is_private != (type == kPrivate)) {
    LOG(ERROR) << "Object privacy mismatch.";
    return false;
  }
  if (!Encrypt(blob, &encrypted_blob)) {
    LOG(ERROR) << "Failed to encrypt object blob.";
    return false;
  }
  if (!WriteBlob(CreateBlobKey(type, handle), encrypted_blob.blob)) {
    LOG(ERROR) << "Failed to write object blob.";
  }
  return true;
}

bool ObjectStoreImpl::LoadPublicObjectBlobs(map<int, ObjectBlob>* blobs) {
  return LoadObjectBlobs(kPublic, blobs);
}

bool ObjectStoreImpl::LoadPrivateObjectBlobs(map<int, ObjectBlob>* blobs) {
  if (key_.empty()) {
    LOG(ERROR) << "The store encryption key has not been initialized.";
    return false;
  }
  return LoadObjectBlobs(kPrivate, blobs);
}

bool ObjectStoreImpl::LoadObjectBlobs(BlobType type,
                                      map<int, ObjectBlob>* blobs) {
  std::unique_ptr<leveldb::Iterator> it(
      db_->NewIterator(leveldb::ReadOptions()));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    BlobType it_type;
    int id = 0;
    if (ParseBlobKey(it->key().ToString(), &it_type, &id) && type == it_type) {
      ObjectBlob encrypted_blob;
      encrypted_blob.is_private = (type == kPrivate);
      encrypted_blob.blob = it->value().ToString();
      ObjectBlob blob;
      if (!Decrypt(encrypted_blob, &blob)) {
        LOG(WARNING) << "Failed to decrypt object blob.";
        continue;
      }
      (*blobs)[id] = blob;
      blob_type_map_[id] = type;
    }
  }
  return true;
}

bool ObjectStoreImpl::Encrypt(const ObjectBlob& plain_text,
                              ObjectBlob* cipher_text) {
  if (plain_text.is_private && key_.empty()) {
    LOG(ERROR) << "The store encryption key has not been initialized.";
    return false;
  }
  cipher_text->is_private = plain_text.is_private;
  SecureBlob obfuscation_key(std::begin(kObfuscationKey),
                             std::end(kObfuscationKey));
  SecureBlob& key = plain_text.is_private ? key_ : obfuscation_key;
  string cipher_text_no_hmac;
  if (!RunCipher(true, key, string(), plain_text.blob, &cipher_text_no_hmac))
    return false;
  // Prepend a version header and include it in the MAC.
  string version_header(1, static_cast<char>(kBlobVersion));
  cipher_text->blob = AppendHMAC(version_header + cipher_text_no_hmac, key);
  return true;
}

bool ObjectStoreImpl::Decrypt(const ObjectBlob& cipher_text,
                              ObjectBlob* plain_text) {
  if (cipher_text.is_private && key_.empty()) {
    LOG(ERROR) << "The store encryption key has not been initialized.";
    return false;
  }
  plain_text->is_private = cipher_text.is_private;
  SecureBlob obfuscation_key(std::begin(kObfuscationKey),
                             std::end(kObfuscationKey));
  SecureBlob& key = cipher_text.is_private ? key_ : obfuscation_key;
  string cipher_text_no_hmac;
  if (!VerifyAndStripHMAC(cipher_text.blob, key, &cipher_text_no_hmac))
    return false;
  // Check and strip the version header.
  int version = static_cast<int>(cipher_text_no_hmac[0]);
  if (version != kBlobVersion) {
    LOG(ERROR) << "Blob found with unknown version.";
    return false;
  }
  cipher_text_no_hmac = cipher_text_no_hmac.substr(1);
  return RunCipher(false, key, string(), cipher_text_no_hmac,
                   &plain_text->blob);
}

string ObjectStoreImpl::AppendHMAC(const string& input, const SecureBlob& key) {
  return input + HmacSha512(input, key);
}

bool ObjectStoreImpl::VerifyAndStripHMAC(const string& input,
                                         const SecureBlob& key,
                                         string* stripped) {
  if (input.size() < static_cast<size_t>(kHMACSizeBytes)) {
    LOG(ERROR) << "Failed to verify blob integrity.";
    return false;
  }
  *stripped = input.substr(0, input.size() - kHMACSizeBytes);
  string hmac = input.substr(input.size() - kHMACSizeBytes);
  string computed_hmac = HmacSha512(*stripped, key);
  if ((hmac.size() != computed_hmac.size()) ||
      (0 !=
       brillo::SecureMemcmp(hmac.data(), computed_hmac.data(), hmac.size()))) {
    LOG(ERROR) << "Failed to verify blob integrity.";
    return false;
  }
  return true;
}

string ObjectStoreImpl::CreateBlobKey(BlobType type, int blob_id) {
  const char* prefix = NULL;
  switch (type) {
    case kInternal:
      prefix = kInternalBlobKeyPrefix;
      break;
    case kPublic:
      prefix = kPublicBlobKeyPrefix;
      break;
    case kPrivate:
      prefix = kPrivateBlobKeyPrefix;
      break;
    default:
      LOG(FATAL) << "Invalid enum value.";
  }
  return base::StringPrintf("%s%s%d", prefix, kBlobKeySeparator, blob_id);
}

bool ObjectStoreImpl::ParseBlobKey(const string& key,
                                   BlobType* type,
                                   int* blob_id) {
  size_t index = key.rfind(kBlobKeySeparator);
  if (index == string::npos) {
    // This isn't a blob.
    return false;
  }
  base::StringPiece key_piece =
      base::MakeStringPiece(key.begin() + (index + 1), key.end());
  if (!base::StringToInt(key_piece, blob_id)) {
    LOG(ERROR) << "Invalid blob key id: " << key;
    return false;
  }
  string prefix = key.substr(0, index);
  if (prefix == kInternalBlobKeyPrefix) {
    *type = kInternal;
  } else if (prefix == kPublicBlobKeyPrefix) {
    *type = kPublic;
  } else if (prefix == kPrivateBlobKeyPrefix) {
    *type = kPrivate;
  } else {
    LOG(ERROR) << "Invalid blob key prefix: " << key;
    return false;
  }
  return true;
}

bool ObjectStoreImpl::GetNextID(int* next_id) {
  if (!ReadInt(kIDTrackerKey, next_id)) {
    LOG(ERROR) << "Failed to read ID tracker.";
    return false;
  }
  if (*next_id == std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Object ID overflow.";
    return false;
  }
  if (!WriteInt(kIDTrackerKey, *next_id + 1)) {
    LOG(ERROR) << "Failed to write ID tracker.";
    return false;
  }
  return true;
}

bool ObjectStoreImpl::ReadBlob(const string& key, string* value) {
  leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, value);
  if (!status.ok()) {
    if (!status.IsNotFound())
      LOG(ERROR) << "Failed to read value from database: " << status.ToString();
    return false;
  }
  return true;
}

bool ObjectStoreImpl::ReadInt(const string& key, int* value) {
  string value_string;
  if (!ReadBlob(key, &value_string))
    return false;
  if (!base::StringToInt(value_string, value)) {
    LOG(ERROR) << "Invalid integer value.";
    return false;
  }
  return true;
}

bool ObjectStoreImpl::WriteBlob(const string& key, const string& value) {
  leveldb::WriteOptions options;
  options.sync = true;
  leveldb::Status status = db_->Put(options, key, value);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to write value to database: " << status.ToString();
    return false;
  }
  return true;
}

bool ObjectStoreImpl::WriteInt(const string& key, int value) {
  return WriteBlob(key, base::NumberToString(value));
}

ObjectStoreImpl::BlobType ObjectStoreImpl::GetBlobType(int blob_id) {
  map<int, BlobType>::iterator it = blob_type_map_.find(blob_id);
  if (it == blob_type_map_.end())
    return kInternal;
  return it->second;
}

}  // namespace chaps
