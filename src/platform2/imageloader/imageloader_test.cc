// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/imageloader_impl.h"

#include <stdint.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "imageloader/component.h"
#include "imageloader/mock_global_context.h"
#include "imageloader/mock_helper_process_proxy.h"
#include "imageloader/test_utilities.h"
#include "imageloader/verity_mounter.h"

namespace imageloader {

using testing::_;

class ImageLoaderTest : public testing::Test {
 public:
  ImageLoaderTest() {
    CHECK(scoped_temp_dir_.CreateUniqueTempDir());
    temp_dir_ = scoped_temp_dir_.GetPath();
    CHECK(base::SetPosixFilePermissions(temp_dir_, kComponentDirPerms));
  }

  void SetUp() override {
    g_ctx_.SetAsCurrent();
    ON_CALL(g_ctx_, IsOfficialBuild()).WillByDefault(testing::Return(true));
  }

  ImageLoaderConfig GetConfig(const char* path) {
    Keys keys;
    keys.push_back(std::vector<uint8_t>(std::begin(kDevPublicKey),
                                        std::end(kDevPublicKey)));
    keys.push_back(std::vector<uint8_t>(std::begin(kOciDevPublicKey),
                                        std::end(kOciDevPublicKey)));
    ImageLoaderConfig config(keys, path, "/foo");
    return config;
  }

  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath temp_dir_;

  MockGlobalContext g_ctx_;
};

// Test the RegisterComponent public interface.
TEST_F(ImageLoaderTest, RegisterComponentAndGetVersion) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  ASSERT_TRUE(loader.RegisterComponent(kTestComponentName, kTestDataVersion,
                                       GetTestComponentPath().value()));

  base::FilePath comp_dir = temp_dir_.Append(kTestComponentName);
  ASSERT_TRUE(base::DirectoryExists(comp_dir));

  base::FilePath hint_file = comp_dir.Append("latest-version");
  ASSERT_TRUE(base::PathExists(hint_file));

  std::string hint_file_contents;
  ASSERT_TRUE(
      base::ReadFileToStringWithMaxSize(hint_file, &hint_file_contents, 4096));
  EXPECT_EQ(kTestDataVersion, hint_file_contents);

  base::FilePath version_dir = comp_dir.Append(kTestDataVersion);
  ASSERT_TRUE(base::DirectoryExists(version_dir));

  // Make sure it actually checks the reported version against the real version.
  EXPECT_FALSE(loader.RegisterComponent(kTestComponentName, kTestUpdatedVersion,
                                        GetTestComponentPath().value()));

  // Now copy a new version into place.
  EXPECT_TRUE(loader.RegisterComponent(
      kTestComponentName, kTestUpdatedVersion,
      GetTestComponentPath(kTestUpdatedVersion).value()));

  std::string hint_file_contents2;
  ASSERT_TRUE(
      base::ReadFileToStringWithMaxSize(hint_file, &hint_file_contents2, 4096));
  EXPECT_EQ(kTestUpdatedVersion, hint_file_contents2);

  base::FilePath version_dir2 = comp_dir.Append(kTestUpdatedVersion);
  ASSERT_TRUE(base::DirectoryExists(version_dir2));

  EXPECT_EQ(kTestUpdatedVersion,
            loader.GetComponentVersion(kTestComponentName));

  // Reject rollback to an older version.
  EXPECT_FALSE(loader.RegisterComponent(kTestComponentName, kTestDataVersion,
                                        GetTestComponentPath().value()));

  EXPECT_EQ(kTestUpdatedVersion,
            loader.GetComponentVersion(kTestComponentName));
}

// Pretend ImageLoader crashed, by creating an incomplete installation, and then
// attempt registration with ImageLoader.
TEST_F(ImageLoaderTest, RegisterComponentAfterCrash) {
  // Now create the junk there.
  const std::string junk_contents = "Bad file contents";
  const base::FilePath junk_path =
      temp_dir_.Append(kTestComponentName).Append(kTestDataVersion);
  ASSERT_TRUE(base::CreateDirectory(junk_path));
  ASSERT_EQ(static_cast<int>(junk_contents.size()),
            base::WriteFile(junk_path.Append("junkfile"), junk_contents.data(),
                            junk_contents.size()));
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  ASSERT_TRUE(loader.RegisterComponent(kTestComponentName, kTestDataVersion,
                                       GetTestComponentPath().value()));
}

TEST_F(ImageLoaderTest, MountValidImage) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendMountCommand(_, _, FileSystem::kSquashFS, _))
      .Times(2);
  ON_CALL(*helper_mock, SendMountCommand(_, _, _, _))
      .WillByDefault(testing::Return(true));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  // We previously tested RegisterComponent, so assume this works if it reports
  // true.
  ASSERT_TRUE(loader.RegisterComponent(kTestComponentName, kTestDataVersion,
                                       GetTestComponentPath().value()));

  const std::string expected_path =
      scoped_mount_dir.GetPath().value() + "/PepperFlashPlayer/22.0.0.158";
  EXPECT_EQ(expected_path,
            loader.LoadComponent(kTestComponentName, helper_mock.get()));

  // Let's also test mounting the component at a fixed point.
  const std::string expected_path2 =
      scoped_mount_dir.GetPath().value() + "/FixedMountPoint";
  EXPECT_TRUE(loader.LoadComponent(kTestComponentName, expected_path2,
                                   helper_mock.get()));
}

TEST_F(ImageLoaderTest, LoadComponentAtPath) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendMountCommand(_, _, FileSystem::kSquashFS, _))
      .Times(1);
  ON_CALL(*helper_mock, SendMountCommand(_, _, _, _))
      .WillByDefault(testing::Return(true));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  const std::string expected_path =
      scoped_mount_dir.GetPath().value() + "/PepperFlashPlayer/22.0.0.158";
  const std::string mnt_path = loader.LoadComponentAtPath(
      kTestComponentName, GetTestComponentPath(), helper_mock.get());
  EXPECT_EQ(expected_path, mnt_path);
}

TEST_F(ImageLoaderTest, CleanupAll) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendUnmountAllCommand(_, _, _)).Times(1);
  ON_CALL(*helper_mock, SendUnmountAllCommand(_, _, _))
      .WillByDefault(testing::Return(true));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  base::FilePath rootpath("/");
  std::vector<std::string> paths;
  EXPECT_EQ(loader.CleanupAll(true, rootpath, &paths, helper_mock.get()), true);
}

TEST_F(ImageLoaderTest, Cleanup) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendUnmountCommand(_)).Times(1);
  ON_CALL(*helper_mock, SendUnmountCommand(_))
      .WillByDefault(testing::Return(true));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  base::FilePath path("/");
  EXPECT_EQ(loader.Cleanup(path, helper_mock.get()), true);
}

TEST_F(ImageLoaderTest, LoadExt4Image) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendMountCommand(_, _, FileSystem::kExt4, _))
      .Times(1);
  ON_CALL(*helper_mock, SendMountCommand(_, _, _, _))
      .WillByDefault(testing::Return(true));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  const std::string expected_path =
      scoped_mount_dir.GetPath().value() + "/ext4/9824.0.4";
  const std::string mnt_path = loader.LoadComponentAtPath(
      "ext4", GetTestDataPath("ext4_component"), helper_mock.get());
  EXPECT_EQ(expected_path, mnt_path);
}

TEST_F(ImageLoaderTest, UnloadDlcImage) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  const std::string dlc_id = "dlc_id";
  const std::string dlc_package = "dlc_package";
  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendUnmountCommand(scoped_mount_dir.GetPath()
                                                   .Append(dlc_id)
                                                   .Append(dlc_package)
                                                   .value()
                                                   .c_str()))
      .Times(1);
  ON_CALL(*helper_mock, SendUnmountCommand(_))
      .WillByDefault(testing::Return(true));

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  loader.UnloadDlcImage(dlc_id, dlc_package, helper_mock.get());
}

TEST_F(ImageLoaderTest, RemoveImageAtPathRemovable) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());
  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  // Make a copy to avoid permanent loss of test data.
  base::ScopedTempDir component_root;
  ASSERT_TRUE(component_root.CreateUniqueTempDir());
  base::FilePath component_path = component_root.GetPath().Append("9824.0.4");
  ASSERT_TRUE(base::CreateDirectory(component_path));
  std::unique_ptr<Component> component = Component::Create(
      base::FilePath(GetTestDataPath("ext4_component")), keys);
  ASSERT_TRUE(component->CopyTo(component_path));

  // Remove the component.
  EXPECT_TRUE(loader.RemoveComponentAtPath("ext4", component_root.GetPath(),
                                           component_path));
  EXPECT_FALSE(base::PathExists(component_root.GetPath()));
}

TEST_F(ImageLoaderTest, RemoveImageAtPathNotRemovable) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());
  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  // Make a copy to avoid permanent loss of test data.
  base::ScopedTempDir component_root;
  ASSERT_TRUE(component_root.CreateUniqueTempDir());
  base::FilePath component_path = component_root.GetPath().Append("9824.0.4");
  ASSERT_TRUE(base::CreateDirectory(component_path));
  std::unique_ptr<Component> component =
      Component::Create(base::FilePath(GetTestComponentPath()), keys);
  ASSERT_TRUE(component->CopyTo(component_path));

  // Remove the component.
  EXPECT_FALSE(loader.RemoveComponentAtPath(
      kTestComponentName, component_root.GetPath(), component_path));
  EXPECT_TRUE(base::PathExists(component_root.GetPath()));
}

TEST_F(ImageLoaderTest, MountInvalidImage) {
  Keys keys;
  keys.push_back(
      std::vector<uint8_t>(std::begin(kDevPublicKey), std::end(kDevPublicKey)));

  auto helper_mock = std::make_unique<MockHelperProcessProxy>();
  EXPECT_CALL(*helper_mock, SendMountCommand(_, _, FileSystem::kSquashFS, _))
      .Times(0);
  ON_CALL(*helper_mock, SendMountCommand(_, _, _, _))
      .WillByDefault(testing::Return(true));

  base::ScopedTempDir scoped_mount_dir;
  ASSERT_TRUE(scoped_mount_dir.CreateUniqueTempDir());

  ImageLoaderConfig config(keys, temp_dir_.value().c_str(),
                           scoped_mount_dir.GetPath().value().c_str());
  ImageLoaderImpl loader(std::move(config));

  // We previously tested RegisterComponent, so assume this works if it reports
  // true.
  ASSERT_TRUE(loader.RegisterComponent(kTestComponentName, kTestDataVersion,
                                       GetTestComponentPath().value()));

  base::FilePath table = temp_dir_.Append(kTestComponentName)
                             .Append(kTestDataVersion)
                             .Append("table");
  std::string contents = "corrupt";
  ASSERT_EQ(static_cast<int>(contents.size()),
            base::WriteFile(table, contents.data(), contents.size()));
  ASSERT_EQ("", loader.LoadComponent(kTestComponentName, helper_mock.get()));
}

TEST_F(ImageLoaderTest, SetupTable) {
  std::string base_table =
      "0 40 verity payload=ROOT_DEV hashtree=HASH_DEV "
      "hashstart=40 alg=sha256 root_hexdigest="
      "34663b9920632778d38a0943a5472cae196bd4bf1d7dfa191506e7a8e7ec84d2 "
      "salt=fcfc9b5a329e44be73a323188ae75ca644122d920161f672f6935623831d07e2";

  // Make sure excess newlines are rejected.
  std::string bad_table = base_table + "\n\n";
  EXPECT_FALSE(VerityMounter::SetupTable(&bad_table, "/dev/loop6"));

  // Make sure it does the right replacements on a simple base table.
  std::string good_table = base_table;
  EXPECT_TRUE(VerityMounter::SetupTable(&good_table, "/dev/loop6"));

  std::string known_good_table =
      "0 40 verity payload=/dev/loop6 hashtree=/dev/loop6 "
      "hashstart=40 alg=sha256 root_hexdigest="
      "34663b9920632778d38a0943a5472cae196bd4bf1d7dfa191506e7a8e7ec84d2 "
      "salt=fcfc9b5a329e44be73a323188ae75ca644122d920161f672f6935623831d07e2 "
      "error_behavior=eio";
  EXPECT_EQ(known_good_table, good_table);

  // Make sure the newline is stripped.
  std::string good_table_newline = base_table + "\n";
  EXPECT_TRUE(VerityMounter::SetupTable(&good_table_newline, "/dev/loop6"));
  EXPECT_EQ(known_good_table, good_table_newline);

  // Make sure error_behavior isn't appended twice.
  std::string good_table_error = base_table + " error_behavior=eio\n";
  EXPECT_TRUE(VerityMounter::SetupTable(&good_table_error, "/dev/loop6"));
  EXPECT_EQ(known_good_table, good_table_error);
}

TEST_F(ImageLoaderTest, SecondKey) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  ASSERT_TRUE(loader.RegisterComponent(kTestOciComponentName,
                                       kTestOciComponentVersion,
                                       GetTestOciComponentPath().value()));

  base::FilePath comp_dir = temp_dir_.Append(kTestOciComponentName);
  ASSERT_TRUE(base::DirectoryExists(comp_dir));

  base::FilePath version_dir = comp_dir.Append(kTestOciComponentVersion);
  ASSERT_TRUE(base::DirectoryExists(version_dir));
}

TEST_F(ImageLoaderTest, GetMetadata) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  ASSERT_TRUE(loader.RegisterComponent(kMetadataComponentName,
                                       kTestOciComponentVersion,
                                       GetMetadataComponentPath().value()));

  // We shouldn't need to load the component to get the metadata.
  std::map<std::string, std::string> metadata;
  ASSERT_TRUE(loader.GetComponentMetadata(kMetadataComponentName, &metadata));
  std::map<std::string, std::string> expected_metadata{
      {"foo", "bar"},
      {"baz", "quux"},
  };
  ASSERT_EQ(expected_metadata, metadata);
}

TEST_F(ImageLoaderTest, GetEmptyMetadata) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  ASSERT_TRUE(loader.RegisterComponent(kTestOciComponentName,
                                       kTestOciComponentVersion,
                                       GetTestOciComponentPath().value()));

  // If there's no metadata, we should get nothing.
  std::map<std::string, std::string> metadata;
  ASSERT_TRUE(loader.GetComponentMetadata(kTestOciComponentName, &metadata));
  ASSERT_TRUE(metadata.empty());
}

TEST_F(ImageLoaderTest, MetadataFailure) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  // Metadata is optional, but malformed metadata should not be present in the
  // manifest. If it is, fail to load the component.
  ASSERT_FALSE(loader.RegisterComponent(kBadMetadataComponentName,
                                        kTestOciComponentVersion,
                                        GetBadMetadataComponentPath().value()));

  ASSERT_FALSE(loader.RegisterComponent(
      kNonDictMetadataComponentName, kTestOciComponentVersion,
      GetNonDictMetadataComponentPath().value()));
}

TEST_F(ImageLoaderTest, ValidIdTest) {
  // alpha numerical IDs:
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("alpha"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("01234"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("alphanum01234"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("01234alphanumerical"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("dash-id0123"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("underscore_id_0123"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("0123-a_dash-id"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid("unicode_id"));
  EXPECT_TRUE(ImageLoaderImpl::IsIdValid(std::string(80, 'a')));
  // first char is illegal:
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid("-non-alpha"));
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid("_non-alpha"));
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid(".non-alpha"));
  // non-alpha numerical IDs:
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid("dot.id"));
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid("../../../../evilid"));
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid("unicode_id_#"));
  // ID is too long.
  EXPECT_FALSE(ImageLoaderImpl::IsIdValid(std::string(81, 'a')));
}

TEST_F(ImageLoaderTest, NoSignatureOfficialImage) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));
  // On official builds a component with no signature file should fail.
  EXPECT_FALSE(loader.RegisterComponent(kNoSignatureComponentName,
                                        kTestOciComponentVersion,
                                        GetNoSignatureComponentPath().value()));
}

TEST_F(ImageLoaderTest, NoSignatureNonOfficialImage) {
  ImageLoaderImpl loader(GetConfig(temp_dir_.value().c_str()));

  // On non-official builds a component with no signature file should succeed.
  EXPECT_CALL(g_ctx_, IsOfficialBuild()).WillRepeatedly(testing::Return(false));
  EXPECT_TRUE(loader.RegisterComponent(kNoSignatureComponentName,
                                       kTestOciComponentVersion,
                                       GetNoSignatureComponentPath().value()));
}

}  // namespace imageloader
