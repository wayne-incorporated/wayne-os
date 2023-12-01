// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/component.h"

#include <stdint.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <crypto/secure_hash.h>
#include <crypto/sha2.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "imageloader/imageloader_impl.h"
#include "imageloader/mock_global_context.h"
#include "imageloader/mock_helper_process_proxy.h"
#include "imageloader/test_utilities.h"

namespace imageloader {

using testing::_;

class ComponentTest : public testing::Test {
 public:
  ComponentTest() {
    keys_.push_back(std::vector<uint8_t>(std::begin(kDevPublicKey),
                                         std::end(kDevPublicKey)));
    CHECK(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
    CHECK(base::SetPosixFilePermissions(temp_dir_, kComponentDirPerms));
  }

  void SetUp() override {
    g_ctx_.SetAsCurrent();
    ON_CALL(g_ctx_, IsOfficialBuild()).WillByDefault(testing::Return(true));
  }

  bool TestCopyWithCorruptFile(const std::string& component_name,
                               const std::string& file_name) {
    base::FilePath bad_component_dir = temp_dir_.Append(component_name);
    if (!base::CreateDirectory(bad_component_dir))
      return false;
    if (!base::SetPosixFilePermissions(bad_component_dir, kComponentDirPerms))
      return false;

    std::unique_ptr<Component> component =
        Component::Create(GetTestComponentPath(), keys_);
    if (!component || !component->CopyTo(bad_component_dir))
      return false;

    std::unique_ptr<Component> bad_component =
        Component::Create(bad_component_dir, keys_);
    if (!bad_component)
      return false;

    base::FilePath file = bad_component_dir.Append(file_name);
    const char data[] = "c";
    // Append to |file| including the trailing '\0' character to fail
    // Component::IsValidFingerprintFile
    if (!base::AppendToFile(file, base::StringPiece(data, sizeof(data))))
      return false;

    base::FilePath bad_component_dest =
        temp_dir_.Append(component_name + "invalid");
    if (!base::CreateDirectory(bad_component_dest))
      return false;

    if (!base::SetPosixFilePermissions(bad_component_dest, kComponentDirPerms))
      return false;
    return bad_component->CopyTo(bad_component_dest) == false;
  }

  bool TestInitComponentWithCorruptFile(const std::string& component_name,
                                        const std::string& file_name) {
    base::FilePath bad_component_dir = temp_dir_.Append(component_name);
    if (!base::CreateDirectory(bad_component_dir))
      return false;
    if (!base::SetPosixFilePermissions(bad_component_dir, kComponentDirPerms))
      return false;

    std::unique_ptr<Component> component =
        Component::Create(GetTestComponentPath(), keys_);
    if (!component || !component->CopyTo(bad_component_dir))
      return false;

    base::FilePath file = bad_component_dir.Append(file_name);
    // Read the file out and change the last byte.
    std::string file_contents;
    if (!base::ReadFileToString(file, &file_contents))
      return false;
    file_contents[file_contents.size() - 1] =
        ~file_contents[file_contents.size() - 1];

    if (!base::WriteFile(file, file_contents.data(), file_contents.size())) {
      return false;
    }

    std::unique_ptr<Component> bad_component =
        Component::Create(bad_component_dir, keys_);
    return bad_component == nullptr;
  }

  bool CompareFileContents(const base::FilePath& src,
                           const base::FilePath& dest,
                           const std::list<std::string>& filenames) {
    for (const std::string& name : filenames) {
      std::string source_file_contents;
      std::string dest_file_contents;
      if (!base::ReadFileToString(src.Append(name), &source_file_contents))
        return false;
      if (!base::ReadFileToString(dest.Append(name), &dest_file_contents))
        return false;
      if (source_file_contents != dest_file_contents) {
        LOG(ERROR) << "File contents does not match for file: " << name;
        return false;
      }
    }
    return true;
  }

  Keys keys_;
  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath temp_dir_;

  MockGlobalContext g_ctx_;
};

TEST_F(ComponentTest, InitComponentAndCheckManifest) {
  std::unique_ptr<Component> component =
      Component::Create(GetTestComponentPath(), keys_);
  ASSERT_NE(nullptr, component);

  EXPECT_EQ(1, component->manifest().manifest_version());
  EXPECT_EQ(kTestDataVersion, component->manifest().version());
  // Don't hardcode the sha256 hashes, but run some validity checks.
  EXPECT_EQ(crypto::kSHA256Length, component->manifest().image_sha256().size());
  EXPECT_EQ(crypto::kSHA256Length, component->manifest().table_sha256().size());
  EXPECT_NE(component->manifest().image_sha256(),
            component->manifest().table_sha256());
}

TEST_F(ComponentTest, TestCopyAndMountComponentExt4) {
  std::unique_ptr<Component> component =
      Component::Create(GetTestDataPath("ext4_component"), keys_);
  ASSERT_NE(nullptr, component);

  const base::FilePath copied_dir = temp_dir_.Append("dest");
  ASSERT_TRUE(base::CreateDirectory(copied_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(copied_dir, kComponentDirPerms));

  ASSERT_TRUE(component->CopyTo(copied_dir));

  std::unique_ptr<Component> copied_component =
      Component::Create(copied_dir, keys_);
  ASSERT_NE(nullptr, copied_component);

  const base::FilePath mount_dir = temp_dir_.Append("mount");
  ASSERT_TRUE(base::CreateDirectory(copied_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(copied_dir, kComponentDirPerms));

  // Note: this fails to test the actual mounting process since it is just a
  // mock here. The platform_ImageLoader autotest tests the real helper
  // process running as a dbus service.
  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendMountCommand(_, _, FileSystem::kExt4, _))
      .Times(1);
  ON_CALL(*helper_mock, SendMountCommand(_, _, _, _))
      .WillByDefault(testing::Return(true));
  ASSERT_TRUE(copied_component->Mount(helper_mock.get(), mount_dir));
}

TEST_F(ComponentTest, TestCopyAndMountComponentSquashfs) {
  std::unique_ptr<Component> component =
      Component::Create(GetTestComponentPath(), keys_);
  ASSERT_NE(nullptr, component);

  const base::FilePath copied_dir = temp_dir_.Append("dest");
  ASSERT_TRUE(base::CreateDirectory(copied_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(copied_dir, kComponentDirPerms));

  ASSERT_TRUE(component->CopyTo(copied_dir));

  std::unique_ptr<Component> copied_component =
      Component::Create(copied_dir, keys_);
  ASSERT_NE(nullptr, copied_component);

  const base::FilePath mount_dir = temp_dir_.Append("mount");
  ASSERT_TRUE(base::CreateDirectory(copied_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(copied_dir, kComponentDirPerms));

  // Note: this fails to test the actual mounting process since it is just a
  // mock here. The platform_ImageLoader autotest tests the real helper
  // process running as a dbus service.
  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendMountCommand(_, _, FileSystem::kSquashFS, _))
      .Times(1);
  ON_CALL(*helper_mock, SendMountCommand(_, _, _, _))
      .WillByDefault(testing::Return(true));
  ASSERT_TRUE(copied_component->Mount(helper_mock.get(), mount_dir));
}

TEST_F(ComponentTest, CheckFilesAfterCopy) {
  std::unique_ptr<Component> component =
      Component::Create(GetTestComponentPath(), keys_);
  ASSERT_NE(nullptr, component);

  const base::FilePath copied_dir = temp_dir_.Append("dest");
  ASSERT_TRUE(base::CreateDirectory(copied_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(copied_dir, kComponentDirPerms));

  ASSERT_TRUE(component->CopyTo(copied_dir));

  std::unique_ptr<Component> copied_component =
      Component::Create(copied_dir, keys_);
  ASSERT_NE(nullptr, copied_component);

  // Check that all the files are present, except for the manifest.json which
  // should be discarded.
  std::list<std::string> original_files;
  std::list<std::string> copied_files;
  GetFilesInDir(GetTestComponentPath(), &original_files);
  GetFilesInDir(copied_dir, &copied_files);

  EXPECT_THAT(original_files,
              testing::UnorderedElementsAre(
                  "imageloader.json", "imageloader.sig.1", "manifest.json",
                  "table", "image.squash", "manifest.fingerprint"));
  ASSERT_THAT(copied_files,
              testing::UnorderedElementsAre(
                  "imageloader.json", "imageloader.sig.1", "table",
                  "image.squash", "manifest.fingerprint"));
  EXPECT_TRUE(
      CompareFileContents(GetTestComponentPath(), copied_dir, copied_files));
}

TEST_F(ComponentTest, CheckNoSignatureComponentFail) {
  EXPECT_FALSE(Component::Create(GetNoSignatureComponentPath(), keys_));
}

TEST_F(ComponentTest, CheckNoSignatureFilesAfterCopy) {
  // Make non-official build.
  EXPECT_CALL(g_ctx_, IsOfficialBuild()).WillRepeatedly(testing::Return(false));

  base::FilePath component_path = GetNoSignatureComponentPath();
  std::unique_ptr<Component> component =
      Component::Create(component_path, keys_);
  ASSERT_TRUE(component);

  const base::FilePath copied_dir = temp_dir_.Append("dest");
  ASSERT_TRUE(base::CreateDirectory(copied_dir));
  ASSERT_TRUE(base::SetPosixFilePermissions(copied_dir, kComponentDirPerms));

  ASSERT_TRUE(component->CopyTo(copied_dir));

  std::unique_ptr<Component> copied_component =
      Component::Create(copied_dir, keys_);
  ASSERT_NE(nullptr, copied_component);

  // Check that all the files are present. The signature file should just be
  // ignored.
  std::list<std::string> original_files;
  std::list<std::string> copied_files;
  GetFilesInDir(component_path, &original_files);
  GetFilesInDir(copied_dir, &copied_files);

  EXPECT_THAT(original_files,
              testing::UnorderedElementsAre("imageloader.json", "manifest.json",
                                            "table", "image.squash"));
  ASSERT_THAT(copied_files, testing::UnorderedElementsAre(
                                "imageloader.json", "table", "image.squash"));
  EXPECT_TRUE(CompareFileContents(component_path, copied_dir, copied_files));
}

TEST_F(ComponentTest, IsValidFingerprintFile) {
  const std::string valid_manifest =
      "1.3464353b1ed78574e05f3ffe84b52582572b2fe7202f3824a3761e54ace8bb1";
  EXPECT_TRUE(Component::IsValidFingerprintFile(valid_manifest));

  const std::string invalid_unicode_manifest = "Ё Ђ Ѓ Є Ѕ І Ї Ј Љ ";
  EXPECT_FALSE(Component::IsValidFingerprintFile(invalid_unicode_manifest));

  EXPECT_FALSE(Component::IsValidFingerprintFile("\x49\x34\x19-43.*+abc"));
}

TEST_F(ComponentTest, InitComponentWithBadFiles) {
  EXPECT_TRUE(
      TestInitComponentWithCorruptFile("bad-component1", "imageloader.json"));
  EXPECT_TRUE(
      TestInitComponentWithCorruptFile("bad-component2", "imageloader.sig.1"));
}

// Now corrupt the manifest of an already initialized component to verify that
// the copy operation fails.
TEST_F(ComponentTest, CopyWithBadFiles) {
  EXPECT_TRUE(TestCopyWithCorruptFile("bad-component1", "image.squash"));
  EXPECT_TRUE(TestCopyWithCorruptFile("bad-component2", "table"));
  EXPECT_TRUE(
      TestCopyWithCorruptFile("bad-component3", "manifest.fingerprint"));
}

TEST_F(ComponentTest, CopyValidImage) {
  const int image_size = 4096 * 4;

  base::FilePath image_path = temp_dir_.Append("image");
  std::vector<char> image(image_size,
                          0xBB);  // large enough to test streaming read.
  ASSERT_EQ(image_size,
            base::WriteFile(image_path, image.data(), image.size()));

  std::vector<uint8_t> hash(crypto::kSHA256Length);

  std::unique_ptr<crypto::SecureHash> sha256(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  sha256->Update(image.data(), image.size());
  sha256->Finish(hash.data(), hash.size());

  Component component(GetTestComponentPath(), 1);
  base::FilePath image_dest = temp_dir_.Append("image.copied");
  ASSERT_TRUE(component.CopyComponentFile(image_path, image_dest, hash));

  // Check if the image file actually exists and has the correct contents.
  std::string resulting_image;
  ASSERT_TRUE(base::ReadFileToStringWithMaxSize(image_dest, &resulting_image,
                                                image_size));

  EXPECT_EQ(0, memcmp(image.data(), resulting_image.data(), image_size));
}

}  // namespace imageloader
