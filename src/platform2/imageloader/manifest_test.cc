// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/values.h>
#include <gtest/gtest.h>

#include "imageloader/manifest.h"

namespace imageloader {

TEST(ManifestTest, ParseManifest) {
  const std::string fs_type = R"("ext4")";
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string id = R"("foo")";
  const std::string name = R"("bar")";
  const std::string image_type = R"("dlc")";
  const std::string preallocated_size = R"("600613")";
  const std::string size = R"("42")";
  const std::string preload_allowed = "true";
  const std::string factory_install = "true";
  const std::string used_by = R"("foo-user")";
  const std::string days_to_purge = R"("3")";
  const std::string mount_file_required = "true";
  const std::string reserved = "true";
  const std::string critical_update = "true";
  const std::string description = R"("foo-description")";
  const std::string manifest_version = "1";
  const std::string use_logical_volume = "true";
  const std::string scaled = "true";
  const std::string powerwash_safe = "true";
  const std::string manifest_raw = std::string() + R"(
    {
    "critical-update":)" + critical_update +
                                   R"(,
    "description":)" + description +
                                   R"(,
    "factory-install":)" + factory_install +
                                   R"(,
    "fs-type":)" + fs_type + R"(,
    "id":)" + id + R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "image-type":)" + image_type + R"(,
    "is-removable":)" + is_removable +
                                   R"(,
    "manifest-version":)" + manifest_version +
                                   R"(,
    "mount-file-required":)" + mount_file_required +
                                   R"(,
    "name":)" + name + R"(,
    "pre-allocated-size":)" + preallocated_size +
                                   R"(,
    "preload-allowed":)" + preload_allowed +
                                   R"(,
    "reserved":)" + reserved + R"(,
    "size":)" + size + R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "used-by":)" + used_by + R"(,
    "days-to-purge":)" + days_to_purge +
                                   R"(,
    "version":)" + version + R"(,
    "use-logical-volume":)" + use_logical_volume +
                                   R"(,
    "scaled":)" + scaled +
                                   R"(,
    "powerwash-safe":)" + powerwash_safe +
                                   R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_TRUE(manifest.ParseManifest(manifest_raw));
  EXPECT_EQ(manifest.fs_type(), FileSystem::kExt4);
  EXPECT_EQ(manifest.is_removable(), true);
  EXPECT_NE(manifest.image_sha256().size(), 0);
  EXPECT_NE(manifest.table_sha256().size(), 0);
  EXPECT_NE(manifest.version().size(), 0);
  EXPECT_EQ(manifest.manifest_version(), 1);
  EXPECT_EQ(manifest.id(), "foo");
  EXPECT_EQ(manifest.name(), "bar");
  EXPECT_EQ(manifest.image_type(), "dlc");
  EXPECT_EQ(manifest.preallocated_size(), 600613);
  EXPECT_EQ(manifest.size(), 42);
  EXPECT_EQ(manifest.preload_allowed(), true);
  EXPECT_EQ(manifest.factory_install(), true);
  EXPECT_EQ(manifest.used_by(), "foo-user");
  EXPECT_EQ(manifest.days_to_purge(), 3);
  EXPECT_EQ(manifest.mount_file_required(), true);
  EXPECT_EQ(manifest.description(), "foo-description");
  EXPECT_EQ(manifest.reserved(), true);
  EXPECT_EQ(manifest.critical_update(), true);
  EXPECT_TRUE(manifest.use_logical_volume());
  EXPECT_TRUE(manifest.scaled());
  EXPECT_TRUE(manifest.powerwash_safe());
}

TEST(ManifestTest, ParseManifestNoOptional) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_TRUE(manifest.ParseManifest(manifest_raw));
  // Should default to squashfs.
  EXPECT_EQ(manifest.fs_type(), FileSystem::kSquashFS);
  EXPECT_EQ(manifest.is_removable(), true);
  EXPECT_NE(manifest.image_sha256().size(), 0);
  EXPECT_NE(manifest.table_sha256().size(), 0);
  EXPECT_NE(manifest.version().size(), 0);
  EXPECT_EQ(manifest.manifest_version(), 1);
  EXPECT_EQ(manifest.preload_allowed(), false);
  EXPECT_EQ(manifest.factory_install(), false);
  EXPECT_EQ(manifest.used_by(), "");
  EXPECT_EQ(manifest.days_to_purge(), 0);
  EXPECT_EQ(manifest.description(), "");
  EXPECT_EQ(manifest.reserved(), false);
  EXPECT_EQ(manifest.critical_update(), false);
  EXPECT_FALSE(manifest.use_logical_volume());
  EXPECT_FALSE(manifest.scaled());
  EXPECT_FALSE(manifest.powerwash_safe());

  // Sizes should default to 0.
  EXPECT_EQ(manifest.preallocated_size(), 0);
  EXPECT_EQ(manifest.size(), 0);
}

TEST(ManifestTest, ParseManifestNoImageHash) {
  const std::string is_removable = "true";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_FALSE(manifest.ParseManifest(manifest_raw));
}

TEST(ManifestTest, ParseManifestNoTableHash) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_FALSE(manifest.ParseManifest(manifest_raw));
}

TEST(ManifestTest, ParseManifestNoVersion) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string manifest_version = "1";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "manifest-version":)" + manifest_version +
                                   R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_FALSE(manifest.ParseManifest(manifest_raw));
}

TEST(ManifestTest, ParseManifestBadPreallocatedSize) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string pre_allocated_size = R"("not a number")";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(,
    "pre-allocated-size":)" + pre_allocated_size +
                                   R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_FALSE(manifest.ParseManifest(manifest_raw));
}

TEST(ManifestTest, ParseManifestBadSize) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string size = R"("not a number")";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(,
    "size":)" + size + R"(
    }
  )";
  Manifest manifest;
  // Parse the manifest raw string.
  ASSERT_FALSE(manifest.ParseManifest(manifest_raw));
}

TEST(ManifestTest, ParseManifestValueDict) {
  const base::Value::Dict manifest_dict =
      base::Value::Dict()
          .Set("fs-type", "ext4")
          .Set("is-removable", true)
          .Set("image-sha256-hash",
               "4CF41BD11362CCB4707FB93939DBB5AC"
               "48745EDFC9DC8D7702852FFAA81B3B3F")
          .Set("table-sha256-hash",
               "0E11DA3D7140C6B95496787F50D15152"
               "434EBA22B60443BFA7E054FF4C799276")
          .Set("version", "9824.0.4")
          .Set("id", "foo")
          .Set("name", "bar")
          .Set("image-type", "dlc")
          .Set("pre-allocated-size", "600613")
          .Set("size", "42")
          .Set("preload-allowed", true)
          .Set("factory-install", true)
          .Set("used-by", "foo-user")
          .Set("days-to-purge", "3")
          .Set("mount-file-required", true)
          .Set("reserved", true)
          .Set("critical-update", true)
          .Set("description", "foo-description")
          .Set("manifest-version", 1)
          .Set("use-logical-volume", true)
          .Set("scaled", true)
          .Set("powerwash-safe", true);
  Manifest manifest;
  // Parse the manifest dict.
  ASSERT_TRUE(manifest.ParseManifest(manifest_dict));
  EXPECT_EQ(manifest.fs_type(), FileSystem::kExt4);
  EXPECT_EQ(manifest.is_removable(), true);
  EXPECT_NE(manifest.image_sha256().size(), 0);
  EXPECT_NE(manifest.table_sha256().size(), 0);
  EXPECT_NE(manifest.version().size(), 0);
  EXPECT_EQ(manifest.manifest_version(), 1);
  EXPECT_EQ(manifest.id(), "foo");
  EXPECT_EQ(manifest.name(), "bar");
  EXPECT_EQ(manifest.image_type(), "dlc");
  EXPECT_EQ(manifest.preallocated_size(), 600613);
  EXPECT_EQ(manifest.size(), 42);
  EXPECT_EQ(manifest.preload_allowed(), true);
  EXPECT_EQ(manifest.factory_install(), true);
  EXPECT_EQ(manifest.used_by(), "foo-user");
  EXPECT_EQ(manifest.days_to_purge(), 3);
  EXPECT_EQ(manifest.mount_file_required(), true);
  EXPECT_EQ(manifest.description(), "foo-description");
  EXPECT_EQ(manifest.reserved(), true);
  EXPECT_EQ(manifest.critical_update(), true);
  EXPECT_TRUE(manifest.use_logical_volume());
  EXPECT_TRUE(manifest.scaled());
  EXPECT_TRUE(manifest.powerwash_safe());
}

TEST(ManifestTest, ManifestComparesEqual) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(
    }
  )";
  Manifest manifest_from_str;
  // Parse the manifest raw string.
  ASSERT_TRUE(manifest_from_str.ParseManifest(manifest_raw));

  const base::Value::Dict manifest_dict =
      base::Value::Dict()
          .Set("is-removable", true)
          .Set("image-sha256-hash",
               "4CF41BD11362CCB4707FB93939DBB5AC"
               "48745EDFC9DC8D7702852FFAA81B3B3F")
          .Set("table-sha256-hash",
               "0E11DA3D7140C6B95496787F50D15152"
               "434EBA22B60443BFA7E054FF4C799276")
          .Set("version", "9824.0.4")
          .Set("manifest-version", 1);

  Manifest manifest_from_val;
  // Parse the manifest dict.
  ASSERT_TRUE(manifest_from_val.ParseManifest(manifest_dict));

  EXPECT_EQ(manifest_from_str, manifest_from_val);
}

TEST(ManifestTest, ManifestComparesNotEqual) {
  const std::string is_removable = "true";
  const std::string image_sha256_hash =
      R"("4CF41BD11362CCB4707FB93939DBB5AC48745EDFC9DC8D7702852FFAA81B3B3F")";
  const std::string table_sha256_hash =
      R"("0E11DA3D7140C6B95496787F50D15152434EBA22B60443BFA7E054FF4C799276")";
  const std::string version = R"("9824.0.4")";
  const std::string manifest_version = "1";
  const std::string manifest_raw = std::string() + R"(
    {
    "is-removable":)" + is_removable +
                                   R"(,
    "image-sha256-hash":)" + image_sha256_hash +
                                   R"(,
    "table-sha256-hash":)" + table_sha256_hash +
                                   R"(,
    "version":)" + version + R"(,
    "manifest-version":)" + manifest_version +
                                   R"(
    }
  )";
  Manifest manifest_from_str;
  // Parse the manifest raw string.
  ASSERT_TRUE(manifest_from_str.ParseManifest(manifest_raw));

  // Create a `base::Value::Dict` and set a different `is-removable` value.
  const base::Value::Dict manifest_dict =
      base::Value::Dict()
          .Set("is-removable", false)
          .Set("image-sha256-hash",
               "4CF41BD11362CCB4707FB93939DBB5AC"
               "48745EDFC9DC8D7702852FFAA81B3B3F")
          .Set("table-sha256-hash",
               "0E11DA3D7140C6B95496787F50D15152"
               "434EBA22B60443BFA7E054FF4C799276")
          .Set("version", "9824.0.4")
          .Set("manifest-version", 1);

  Manifest manifest_from_val;
  // Parse the manifest dict.
  ASSERT_TRUE(manifest_from_val.ParseManifest(manifest_dict));

  EXPECT_FALSE(manifest_from_str == manifest_from_val);
}

}  // namespace imageloader
