// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_store_impl.h"

#include <map>
#include <string>

#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <metrics/metrics_library_mock.h>

using base::FilePath;
using brillo::SecureBlob;
using std::map;
using std::string;
using ::testing::StrictMock;

namespace chaps {

class TestObjectStoreEncryption : public ::testing::Test {
 public:
  bool TestEncryption(ObjectStoreImpl& store,  // NOLINT(runtime/references)
                      const ObjectBlob& input) {
    ObjectBlob encrypted;
    if (!store.Encrypt(input, &encrypted))
      return false;
    ObjectBlob decrypted;
    if (!store.Decrypt(encrypted, &decrypted))
      return false;
    return (Equals(input, decrypted));
  }
  ObjectBlob MakeBlob(string blob_data) {
    ObjectBlob blob = {blob_data, true};
    return blob;
  }
  bool Equals(const ObjectBlob& blob1, const ObjectBlob& blob2) {
    return (blob1.is_private == blob2.is_private && blob1.blob == blob2.blob);
  }
};

TEST_F(TestObjectStoreEncryption, EncryptionInit) {
  ObjectStoreImpl store;
  ObjectBlob input = MakeBlob(string(10, 0x00)), output;
  EXPECT_FALSE(store.Encrypt(input, &output));
  EXPECT_FALSE(store.Decrypt(input, &output));
  EXPECT_FALSE(store.SetEncryptionKey(SecureBlob(0, 0)));
  EXPECT_FALSE(store.SetEncryptionKey(SecureBlob(16, 0xAA)));
  EXPECT_FALSE(store.SetEncryptionKey(SecureBlob(31, 0xAA)));
  EXPECT_FALSE(store.SetEncryptionKey(SecureBlob(33, 0xAA)));
  EXPECT_TRUE(store.SetEncryptionKey(SecureBlob(32, 0xAA)));
  EXPECT_TRUE(TestEncryption(store, input));
}

TEST_F(TestObjectStoreEncryption, Encryption) {
  ObjectStoreImpl store;
  SecureBlob key(SecureBlob(32, 0xAA));
  ASSERT_TRUE(store.SetEncryptionKey(key));
  ObjectBlob blob = MakeBlob(string(64, 0xBB));
  // On AES block boundary.
  EXPECT_TRUE(TestEncryption(store, blob));
  // Not on AES block boundary.
  EXPECT_TRUE(TestEncryption(store, MakeBlob(string(21, 0xCC))));
  // One over AES block boundary.
  EXPECT_TRUE(TestEncryption(store, MakeBlob(string(33, 0xDD))));
  // One under AES block boundary.
  EXPECT_TRUE(TestEncryption(store, MakeBlob(string(31, 0xEE))));
  // Zero length input.
  EXPECT_TRUE(TestEncryption(store, MakeBlob(string())));
  // Test random IV: two identical blobs should have different cipher texts.
  ObjectBlob encrypted1;
  EXPECT_TRUE(store.Encrypt(blob, &encrypted1));
  EXPECT_EQ(blob.is_private, encrypted1.is_private);
  ObjectBlob encrypted2;
  EXPECT_TRUE(store.Encrypt(blob, &encrypted2));
  EXPECT_TRUE(encrypted1.blob != encrypted2.blob);
  ObjectBlob decrypted1;
  EXPECT_TRUE(store.Decrypt(encrypted1, &decrypted1));
  EXPECT_TRUE(Equals(decrypted1, blob));
  ObjectBlob decrypted2;
  EXPECT_TRUE(store.Decrypt(encrypted2, &decrypted2));
  EXPECT_TRUE(Equals(decrypted2, blob));
  // Invalid decrypt.
  EXPECT_FALSE(store.Decrypt(blob, &decrypted1));
  // Test corrupted IV.
  ObjectBlob encrypted_ok = encrypted1;
  encrypted1.blob[encrypted1.blob.size() - 1]++;
  EXPECT_FALSE(store.Decrypt(encrypted1, &decrypted1));
  // Test corrupted cipher text.
  encrypted1 = encrypted_ok;
  encrypted1.blob[0]++;
  EXPECT_FALSE(store.Decrypt(encrypted1, &decrypted1));
  // Test corrupted hmac.
  encrypted1 = encrypted_ok;
  encrypted1.blob[encrypted1.blob.size() - 17]++;
  EXPECT_FALSE(store.Decrypt(encrypted1, &decrypted1));
  // Test public blob.
  ObjectBlob public_blob = {blob.blob, false};
  EXPECT_TRUE(store.Encrypt(public_blob, &encrypted1));
  EXPECT_FALSE(encrypted1.is_private);
  EXPECT_TRUE(store.Decrypt(encrypted1, &decrypted1));
  EXPECT_TRUE(Equals(public_blob, decrypted1));
}

TEST_F(TestObjectStoreEncryption, CBCMode) {
  ObjectStoreImpl store;
  SecureBlob key(SecureBlob(32, 0xAA));
  ASSERT_TRUE(store.SetEncryptionKey(key));
  ObjectBlob two_identical_blocks = MakeBlob(string(32, 0xBB));
  ObjectBlob encrypted;
  EXPECT_TRUE(store.Encrypt(two_identical_blocks, &encrypted));
  string encrypted_block1 = encrypted.blob.substr(0, 16);
  string encrypted_block2 = encrypted.blob.substr(16, 16);
  EXPECT_FALSE(encrypted_block1 == encrypted_block2);
}

TEST(TestObjectStore, DBInitFail) {
  // Note that we're unable to test kDatabaseCreateFailure reliably so it's
  // not tested.

  ObjectStoreImpl store;
  const char database[] = "/dev/null";
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);

  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseOpenAttempt));
  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseCorrupted));
  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseRepairFailure));
  ASSERT_FALSE(store.Init(FilePath(database), &chaps_metrics));
}

TEST(TestObjectStore, InsertLoad) {
  ObjectStoreImpl store;
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseOpenAttempt));
  EXPECT_CALL(mock_metrics_library,
              SendCrosEventToUMA(kDatabaseOpenedSuccessfully));
  ASSERT_TRUE(store.Init(tmp_dir.GetPath(), &chaps_metrics));
  string tmp(32, 'A');
  SecureBlob key(tmp.begin(), tmp.end());
  EXPECT_TRUE(store.SetEncryptionKey(key));
  map<int, ObjectBlob> objects, objects2;
  EXPECT_TRUE(store.LoadPublicObjectBlobs(&objects));
  EXPECT_TRUE(store.LoadPrivateObjectBlobs(&objects2));
  EXPECT_EQ(0, objects.size());
  EXPECT_EQ(0, objects2.size());
  int handle1;
  ObjectBlob blob1 = {"blob1", false};
  EXPECT_TRUE(store.InsertObjectBlob(blob1, &handle1));
  int handle2;
  ObjectBlob blob2 = {"blob2", false};
  EXPECT_TRUE(store.InsertObjectBlob(blob2, &handle2));
  int handle3;
  ObjectBlob blob3 = {"blob3", true};
  EXPECT_TRUE(store.InsertObjectBlob(blob3, &handle3));
  int handle4;
  ObjectBlob blob4 = {"blob4", true};
  EXPECT_TRUE(store.InsertObjectBlob(blob4, &handle4));
  EXPECT_TRUE(store.LoadPublicObjectBlobs(&objects));
  EXPECT_TRUE(store.LoadPrivateObjectBlobs(&objects2));
  EXPECT_EQ(2, objects.size());
  EXPECT_EQ(2, objects2.size());
  EXPECT_TRUE(objects.end() != objects.find(handle1));
  EXPECT_TRUE(objects.end() != objects.find(handle2));
  EXPECT_TRUE(objects2.end() != objects2.find(handle3));
  EXPECT_TRUE(objects2.end() != objects2.find(handle4));
  EXPECT_TRUE(blob1.blob == objects[handle1].blob);
  EXPECT_TRUE(blob2.blob == objects[handle2].blob);
  EXPECT_TRUE(blob3.blob == objects2[handle3].blob);
  EXPECT_TRUE(blob4.blob == objects2[handle4].blob);
  EXPECT_FALSE(objects[handle1].is_private);
  EXPECT_FALSE(objects[handle2].is_private);
  EXPECT_TRUE(objects2[handle3].is_private);
  EXPECT_TRUE(objects2[handle4].is_private);
}

TEST(TestObjectStore, UpdateDelete) {
  ObjectStoreImpl store;
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseOpenAttempt));
  EXPECT_CALL(mock_metrics_library,
              SendCrosEventToUMA(kDatabaseOpenedSuccessfully));
  ASSERT_TRUE(store.Init(tmp_dir.GetPath(), &chaps_metrics));
  string tmp(32, 'A');
  SecureBlob key(tmp.begin(), tmp.end());
  EXPECT_TRUE(store.SetEncryptionKey(key));
  int handle1;
  ObjectBlob blob1 = {"blob1", false};
  EXPECT_TRUE(store.InsertObjectBlob(blob1, &handle1));
  map<int, ObjectBlob> objects;
  EXPECT_TRUE(store.LoadPublicObjectBlobs(&objects));
  EXPECT_TRUE(blob1.blob == objects[handle1].blob);
  ObjectBlob blob2 = {"blob2", false};
  EXPECT_TRUE(store.UpdateObjectBlob(handle1, blob2));
  EXPECT_TRUE(store.LoadPublicObjectBlobs(&objects));
  EXPECT_EQ(1, objects.size());
  EXPECT_TRUE(blob2.blob == objects[handle1].blob);
  ObjectBlob bad_priv_setting = {"blob3", true};
  EXPECT_FALSE(store.UpdateObjectBlob(handle1, bad_priv_setting));
  EXPECT_TRUE(store.DeleteObjectBlob(handle1));
  objects.clear();
  EXPECT_TRUE(store.LoadPublicObjectBlobs(&objects));
  EXPECT_EQ(0, objects.size());
}

TEST(TestObjectStore, InternalBlobs) {
  ObjectStoreImpl store;
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseOpenAttempt));
  EXPECT_CALL(mock_metrics_library,
              SendCrosEventToUMA(kDatabaseOpenedSuccessfully));
  ASSERT_TRUE(store.Init(tmp_dir.GetPath(), &chaps_metrics));
  string blob;
  EXPECT_FALSE(store.GetInternalBlob(1, &blob));
  EXPECT_TRUE(store.SetInternalBlob(1, "blob"));
  EXPECT_TRUE(store.GetInternalBlob(1, &blob));
  EXPECT_EQ("blob", blob);
}

TEST(TestObjectStore, DeleteAll) {
  ObjectStoreImpl store;
  base::ScopedTempDir tmp_dir;
  ASSERT_TRUE(tmp_dir.CreateUniqueTempDir());
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(mock_metrics_library, SendCrosEventToUMA(kDatabaseOpenAttempt));
  EXPECT_CALL(mock_metrics_library,
              SendCrosEventToUMA(kDatabaseOpenedSuccessfully));
  ASSERT_TRUE(store.Init(tmp_dir.GetPath(), &chaps_metrics));
  string tmp(32, 'A');
  SecureBlob key(tmp.begin(), tmp.end());
  EXPECT_TRUE(store.SetEncryptionKey(key));
  // Insert a few blobs and make sure only internal blobs survive DeleteAll.
  int handle1;
  ObjectBlob blob1 = {"blob1", false};
  EXPECT_TRUE(store.InsertObjectBlob(blob1, &handle1));
  int handle2;
  ObjectBlob blob2 = {"blob2", true};
  EXPECT_TRUE(store.InsertObjectBlob(blob2, &handle2));
  EXPECT_TRUE(store.SetInternalBlob(1, "internal"));
  EXPECT_TRUE(store.DeleteAllObjectBlobs());
  map<int, ObjectBlob> objects, objects2;
  EXPECT_TRUE(store.LoadPublicObjectBlobs(&objects));
  EXPECT_TRUE(store.LoadPrivateObjectBlobs(&objects2));
  EXPECT_EQ(0, objects.size());
  EXPECT_EQ(0, objects2.size());
  string internal;
  EXPECT_TRUE(store.GetInternalBlob(1, &internal));
  EXPECT_EQ("internal", internal);
}

}  // namespace chaps

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ERR_load_crypto_strings();
  // /dev/urandom is not available in qemu so give some fake entropy.
  unsigned char seed[256];
  RAND_seed(seed, sizeof(seed));
  return RUN_ALL_TESTS();
}
