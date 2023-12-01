// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <libdevmapper.h>

#include <base/files/file_util.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/blkdev_utils/device_mapper_fake.h>
#include <gtest/gtest.h>

namespace brillo {

TEST(DevmapperTableTest, CreateTableFromSecureBlobTest) {
  SecureBlob crypt_table_str("0 100 crypt");

  DevmapperTable dm_table =
      DevmapperTable::CreateTableFromSecureBlob(crypt_table_str);
  EXPECT_EQ(DevmapperTable(0, 0, "", SecureBlob()).ToSecureBlob(),
            dm_table.ToSecureBlob());
}

TEST(DevmapperTableTest, CryptCreateParametersTest) {
  base::FilePath device("/some/random/filepath");

  SecureBlob secret("0123456789ABCDEF");

  SecureBlob crypt_parameters = DevmapperTable::CryptCreateParameters(
      "aes-cbc-essiv:sha256", secret, 0, device, 0, true);

  DevmapperTable crypt_table(0, 100, "crypt", crypt_parameters);

  SecureBlob crypt_table_str(
      "0 100 crypt aes-cbc-essiv:sha256 "
      "0123456789ABCDEF 0 /some/random/filepath 0 1 "
      "allow_discards");

  EXPECT_EQ(crypt_table.ToSecureBlob().to_string(),
            crypt_table_str.to_string());
}

TEST(DevmapperTableTest, CryptCreateTableFromSecureBlobTest) {
  base::FilePath device("/some/random/filepath");

  SecureBlob secret("0123456789ABCDEF");

  SecureBlob crypt_parameters = DevmapperTable::CryptCreateParameters(
      "aes-cbc-essiv:sha256", secret, 0, device, 0, true);

  DevmapperTable crypt_table(0, 100, "crypt", crypt_parameters);

  SecureBlob crypt_table_str(
      "0 100 crypt aes-cbc-essiv:sha256 "
      "0123456789ABCDEF 0 /some/random/filepath 0 1 "
      "allow_discards");

  DevmapperTable parsed_blob_table =
      DevmapperTable::CreateTableFromSecureBlob(crypt_table_str);

  EXPECT_EQ(crypt_table.ToSecureBlob(), parsed_blob_table.ToSecureBlob());
}

TEST(DevmapperTableTest, CryptGetKeyTest) {
  SecureBlob secret("0123456789ABCDEF");
  SecureBlob crypt_table_str(
      "0 100 crypt aes-cbc-essiv:sha256 "
      "0123456789ABCDEF 0 /some/random/filepath 0 1 "
      "allow_discards");

  DevmapperTable dm_table =
      DevmapperTable::CreateTableFromSecureBlob(crypt_table_str);

  EXPECT_EQ(secret, dm_table.CryptGetKey());
}

TEST(DevmapperTableTest, MalformedCryptTableTest) {
  SecureBlob secret;
  SecureBlob::HexStringToSecureBlob("0123456789ABCDEF", &secret);
  // Pass malformed crypt table string.
  SecureBlob crypt_table_str(
      "0 100 crypt ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ");

  DevmapperTable dm_table =
      DevmapperTable::CreateTableFromSecureBlob(crypt_table_str);

  EXPECT_EQ(SecureBlob(), dm_table.CryptGetKey());
}

TEST(DevmapperTableTest, GetterTest) {
  SecureBlob verity_table(
      "0 40 verity payload=/dev/loop6 hashtree=/dev/loop6 "
      "hashstart=40 alg=sha256 root_hexdigest="
      "01234567 "
      "salt=89ABCDEF "
      "error_behavior=eio");

  DevmapperTable dm_table =
      DevmapperTable::CreateTableFromSecureBlob(verity_table);

  EXPECT_EQ(dm_table.GetStart(), 0);
  EXPECT_EQ(dm_table.GetSize(), 40);
  EXPECT_EQ(dm_table.GetType(), "verity");
  EXPECT_EQ(dm_table.GetParameters(),
            SecureBlob("payload=/dev/loop6 hashtree=/dev/loop6 "
                       "hashstart=40 alg=sha256 root_hexdigest=01234567 "
                       "salt=89ABCDEF error_behavior=eio"));
}

TEST(DevmapperTest, FakeTaskConformance) {
  SecureBlob secret("0123456789ABCDEF");
  SecureBlob crypt_table_str(
      "0 100 crypt aes-cbc-essiv:sha256 "
      "0123456789ABCDEF 0 /some/random/filepath 0 1 "
      "allow_discards");

  DevmapperTable dm_table =
      DevmapperTable::CreateTableFromSecureBlob(crypt_table_str);

  EXPECT_EQ(secret, dm_table.CryptGetKey());
  DeviceMapper dm(base::BindRepeating(&fake::CreateDevmapperTask));

  // Add device.
  EXPECT_TRUE(dm.Setup("abcd", dm_table));
  EXPECT_FALSE(dm.Setup("abcd", dm_table));
  DevmapperTable table = dm.GetTable("abcd");
  // Expect tables to be the same.
  EXPECT_EQ(table.ToSecureBlob(), dm_table.ToSecureBlob());
  // Expect key to match.
  EXPECT_EQ(table.CryptGetKey(), secret);
  EXPECT_TRUE(dm.Remove("abcd"));
  EXPECT_FALSE(dm.Remove("abcd"));
}

}  // namespace brillo
