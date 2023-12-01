// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/fake_mount_mapper.h"

#include <list>
#include <map>
#include <memory>

#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/fake_platform/fake_fake_mount_mapping_redirect_factory.h"
#include "cryptohome/fake_platform/test_file_path.h"

namespace cryptohome {

namespace {
constexpr char kFile[] = "file";
constexpr char kDirectory[] = "dir";
}  // namespace

class FakeMountMapperTest : public ::testing::Test {
 public:
  FakeMountMapperTest()
      : fake_mapper_(std::make_unique<FakeMountMapper>(
            kRoot,
            std::make_unique<FakeFakeMountMappingRedirectFactory>(
                std::list<base::FilePath>{kRedirect1, kRedirect2,
                                          kRedirect3}))) {}

 protected:
  // NOTE: mounts and binds done in the test may not represent mounts and binds
  // that happen in the real system, this file just tests the behaviour of the
  // mapper.
  const base::FilePath kRoot{"/tmp/root"};
  const base::FilePath kRedirect1{"/tmp/redirect1"};
  const base::FilePath kRedirect2{"/tmp/redirect2"};
  const base::FilePath kRedirect3{"/tmp/redirect3"};
  const base::FilePath kSource1{"/home/.shadow/0001/mount"};
  const base::FilePath kSource2{"/home/.shadow/0010/mount"};
  const base::FilePath kSource3{"/home/.shadow/0100/mount"};
  const base::FilePath kTarget0{"/home/user/chronos/"};
  const base::FilePath kTarget0Directory{"/home/user/chronos/dir"};
  const base::FilePath kTarget0Directory2{"/home/user/chronos/dir2"};
  const base::FilePath kTarget0InnerDirectory{"/home/user/chronos/dir2/dir3"};
  const base::FilePath kTarget0File{"/home/user/chronos/file"};
  const base::FilePath kTarget1{"/home/user/u-0001"};
  const base::FilePath kTarget1File{"/home/user/u-0001/file"};
  const base::FilePath kTarget2{"/home/user/u-0010"};
  const base::FilePath kTarget2File{"/home/user/u-0010/file"};
  const base::FilePath kTarget3{"/home/user/u-0100"};
  const base::FilePath kTarget3File{"/home/user/u-0100/file"};
  const base::FilePath kTarget4{"/home/user/u-1000"};
  const base::FilePath kTarget4File{"/home/user/u-1000/file"};
  const base::FilePath kTarget5{"/home/user/u-aaaa"};
  const base::FilePath kTarget5File{"/home/user/u-aaaa/file"};

  const std::unique_ptr<FakeMountMapper> fake_mapper_;
};

namespace {

using ::testing::Eq;
using ::testing::UnorderedElementsAreArray;

TEST_F(FakeMountMapperTest, SimpleMountRedirectUnmountChecks) {
  // Test that mount and unmount sequence works, and path resolution produces
  // expected values.

  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Mount(kSource2, kTarget2));

  // Check redirects are correct (from the redirect factory)
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1), Eq(kRedirect1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kFile)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2), Eq(kRedirect2));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2File),
              Eq(kRedirect2.Append(kFile)));

  // Mount the same source to a different target
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));

  // Should appear on the same redirect
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0), Eq(kRedirect1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(kRedirect1.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));

  // Now resolve should return the files itself
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kTarget0File)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kTarget1File)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kTarget2File)));

  // Another unmount should fail
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget0));
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget1));
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget2));

  // Mount in a different order
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Mount(kSource2, kTarget2));
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget1));

  // Check redirects are still correct
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0), Eq(kRedirect1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(kRedirect1.Append(kFile)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1), Eq(kRedirect1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kFile)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2), Eq(kRedirect2));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2File),
              Eq(kRedirect2.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));
}

TEST_F(FakeMountMapperTest, SimpleBindRedirectUnmountChecks) {
  // Test that bind and unmount sequence works, and path resolution produces
  // expected values.

  // Bind
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));

  // Check redirects are correct (tmpfs location of the source)
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget1File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource2)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget2File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource2).Append(kFile)));

  // Bind the same source to a different target
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));

  // Should appear on the same redirect
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget0File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));

  // Now resolve should return the files itself
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kTarget0File)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kTarget1File)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kTarget2File)));

  // Another unmount should fail
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget0));
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget1));
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget2));

  // Bind in a different order
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));

  // Check redirects are still correct
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget0File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget1File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget2),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource2)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget2File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource2).Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));
}

TEST_F(FakeMountMapperTest, SourceRedirectMountConsistency) {
  // Check the redirect stays the same across multiple mount/unmount calls.

  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));

  // Check redirects is correct
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(kRedirect1.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));

  // Mount another source onto the same target
  ASSERT_TRUE(fake_mapper_->Mount(kSource2, kTarget0));

  // Check redirects is correct (different from the first case)
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(kRedirect2.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));

  // Mount the first source again
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));

  // Check redirects is correct (the same with the first case).
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0File),
              Eq(kRedirect1.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, SourceRedirectBindConsistency) {
  // Check the redirect stays the same across multiple bind/unmount calls.

  // Bind
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));

  // Check redirects is correct
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget0File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));

  // Bind another source onto the same target
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget0));

  // Check redirects is correct (different from the first case)
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget0File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource2).Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));

  // Bind the first source again
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));

  // Check redirects is correct (the same with the first casE).
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget0File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, BusyUnmount_SelfBindIsNotBusy) {
  // Check that self Bind can unmount
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kSource1));
  ASSERT_TRUE(fake_mapper_->Unmount(kSource1));
}

TEST_F(FakeMountMapperTest, BusyUnmount_DirectMapping) {
  // Check that parent mount can not be unmounted before dependent one.
  // In this test the target of parent is the exact source for child.

  // Mount a chain
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0, kTarget1));

  // Verify redirect
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kFile)));

  // Unmounting in the wrong order should fail
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget0));

  // Verify redirect
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kFile)));

  // Unmounting in the correct order succeeds
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, BusyUnmount_InnerPathMapping) {
  // Check that parent mount can not be unmounted before dependent one.
  // In this test a path within the target of parent is the source for child.

  // Mount a chain
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0Directory, kTarget1));

  // Verify redirect
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kDirectory).Append(kFile)));

  // Unmounting in the wrong order should fail
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget0));

  // Verify redirect
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kDirectory).Append(kFile)));

  // Unmounting in the correct order succeeds
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, MultipleMountsShouldFail) {
  // Second mount to the same target should fail, but the first mount
  // is still ok after that.
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget1));
  ASSERT_FALSE(fake_mapper_->Mount(kSource2, kTarget1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kFile)));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));

  // Repeat other way around
  ASSERT_TRUE(fake_mapper_->Mount(kSource2, kTarget1));
  ASSERT_FALSE(fake_mapper_->Mount(kSource1, kTarget1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect2.Append(kFile)));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
}

TEST_F(FakeMountMapperTest, MultipleBindShouldFail) {
  // Second bind to the same target should fail, but the first bind
  // is still ok after that.
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));
  ASSERT_FALSE(fake_mapper_->Bind(kSource2, kTarget1));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget1File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));

  // Repeat other way around
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget1));
  ASSERT_FALSE(fake_mapper_->Bind(kSource1, kTarget1));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget1File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource2).Append(kFile)));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
}

TEST_F(FakeMountMapperTest, MultipleUnmountShouldFail) {
  // Unmounting not mounted target should fail.
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget1));
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget2));

  // Mount and Bind
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));

  // Now unmount.
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));

  // Subsequent unmount should fail.
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget1));
  ASSERT_FALSE(fake_mapper_->Unmount(kTarget2));
}

TEST_F(FakeMountMapperTest, ResolveMountBindChain) {
  // Check the Mount->Bind->File chain is resolved correctly.

  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0, kTarget1));

  // File is on the factory created redirect of the first mount.
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1), Eq(kRedirect1));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kFile)));

  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(kRedirect1.Append(kFile), kTarget0),
      Eq(kTarget0.Append(kFile)));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(kRedirect1, kTarget0),
              Eq(kTarget0));
  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(kRedirect1.Append(kFile), kTarget1),
      Eq(kTarget1File));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(kRedirect1, kTarget1),
              Eq(kTarget1));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ResolveMountInnerBindChain) {
  // Check the Mount->Subdirectory Bind->File chain is resolved correctly.

  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0Directory, kTarget1));

  // File is on the factory created redirect of the first mount with relative
  // path.
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1),
              Eq(kRedirect1.Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(kRedirect1.Append(kDirectory).Append(kFile)));

  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(kRedirect1.Append(kDirectory), kTarget0),
      Eq(kTarget0.Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  kRedirect1.Append(kDirectory).Append(kFile), kTarget0),
              Eq(kTarget0.Append(kDirectory).Append(kFile)));
  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(kRedirect1.Append(kDirectory), kTarget1),
      Eq(kTarget1));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  kRedirect1.Append(kDirectory).Append(kFile), kTarget1),
              Eq(kTarget1File));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ResolveSameTargetPrefixMountBindChain) {
  // Check the Mount->Subdirectory Bind->File chain is resolved correctly when
  // there is a matching target prefix

  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0Directory, kTarget0InnerDirectory));

  // File is on the source location of the first mount with relative path.
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0InnerDirectory),
              Eq(kRedirect1.Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0InnerDirectory.Append(kFile)),
              Eq(kRedirect1.Append(kDirectory).Append(kFile)));

  EXPECT_THAT(fake_mapper_->ReverseResolvePath(kRedirect1.Append(kDirectory),
                                               kTarget0InnerDirectory),
              Eq(kTarget0InnerDirectory));
  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(
          kRedirect1.Append(kDirectory).Append(kFile), kTarget0InnerDirectory),
      Eq(kTarget0InnerDirectory.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0InnerDirectory));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ResolveBindBindChain) {
  // Check the Bind->Bind->File chain is resolved correctly.

  // Mount
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0, kTarget1));

  // File is on the source location of the first mount.
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)));
  EXPECT_THAT(
      fake_mapper_->ResolvePath(kTarget1File),
      Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile)));

  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  fake_platform::SpliceTestFilePath(kRoot, kSource1), kTarget0),
              Eq(kTarget0));
  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(
          fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile),
          kTarget0),
      Eq(kTarget0.Append(kFile)));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  fake_platform::SpliceTestFilePath(kRoot, kSource1), kTarget1),
              Eq(kTarget1));
  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(
          fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kFile),
          kTarget1),
      Eq(kTarget1.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ResolveBindInnerBindChain) {
  // Check the Bind->Subdirectory Bind->File chain is resolved correctly.

  // Mount
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0Directory, kTarget1));

  // File is on the source location of the first mount with relative path.
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)
                     .Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget1File),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)
                     .Append(kDirectory)
                     .Append(kFile)));

  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(
          fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kDirectory),
          kTarget0),
      Eq(kTarget0.Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  fake_platform::SpliceTestFilePath(kRoot, kSource1)
                      .Append(kDirectory)
                      .Append(kFile),
                  kTarget0),
              Eq(kTarget0.Append(kDirectory).Append(kFile)));
  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(
          fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kDirectory),
          kTarget1),
      Eq(kTarget1));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  fake_platform::SpliceTestFilePath(kRoot, kSource1)
                      .Append(kDirectory)
                      .Append(kFile),
                  kTarget1),
              Eq(kTarget1File));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ResolveSameTargetPrefixBindBindChain) {
  // Check the Bind->Subdirectory Bind->File chain is resolved correctly when
  // there is a matching target prefix

  // Mount
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0Directory, kTarget0InnerDirectory));

  // File is on the source location of the first mount with relative path.
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0InnerDirectory),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)
                     .Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0InnerDirectory.Append(kFile)),
              Eq(fake_platform::SpliceTestFilePath(kRoot, kSource1)
                     .Append(kDirectory)
                     .Append(kFile)));

  EXPECT_THAT(
      fake_mapper_->ReverseResolvePath(
          fake_platform::SpliceTestFilePath(kRoot, kSource1).Append(kDirectory),
          kTarget0InnerDirectory),
      Eq(kTarget0InnerDirectory));
  EXPECT_THAT(fake_mapper_->ReverseResolvePath(
                  fake_platform::SpliceTestFilePath(kRoot, kSource1)
                      .Append(kDirectory)
                      .Append(kFile),
                  kTarget0InnerDirectory),
              Eq(kTarget0InnerDirectory.Append(kFile)));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0InnerDirectory));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ResolveMountSelfBind) {
  // Check that self Bind can resolve correctly.
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kTarget0Directory, kTarget0Directory));

  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0Directory),
              Eq(kRedirect1.Append(kDirectory)));
  EXPECT_THAT(fake_mapper_->ResolvePath(kTarget0Directory.Append(kFile)),
              Eq(kRedirect1.Append(kDirectory).Append(kFile)));

  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0Directory));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, Check_IsMounted) {
  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));
  ASSERT_TRUE(fake_mapper_->Mount(kSource3, kTarget3));
  ASSERT_TRUE(fake_mapper_->Mount(kTarget1, kTarget4));

  // Check IsMounted returns true only for the target paths which are mapped
  EXPECT_TRUE(fake_mapper_->IsMounted(kTarget0));
  EXPECT_TRUE(fake_mapper_->IsMounted(kTarget1));
  EXPECT_TRUE(fake_mapper_->IsMounted(kTarget2));
  EXPECT_TRUE(fake_mapper_->IsMounted(kTarget3));
  EXPECT_TRUE(fake_mapper_->IsMounted(kTarget4));
  EXPECT_FALSE(fake_mapper_->IsMounted(kTarget5));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget4));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget3));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, Check_IsOnMount) {
  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));
  ASSERT_TRUE(fake_mapper_->Mount(kSource3, kTarget3));
  ASSERT_TRUE(fake_mapper_->Mount(kTarget1, kTarget4));

  // Check IsOnMount returns true for the mapped targets ...
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget0));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget1));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget2));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget3));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget4));
  EXPECT_FALSE(fake_mapper_->IsOnMount(kTarget5));

  // ... and the paths under them
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget0File));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget1File));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget2File));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget3File));
  EXPECT_TRUE(fake_mapper_->IsOnMount(kTarget4File));
  EXPECT_FALSE(fake_mapper_->IsOnMount(kTarget5File));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget4));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget3));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ListMountsBySourcePrefix_String) {
  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));
  ASSERT_TRUE(fake_mapper_->Mount(kSource3, kTarget3));

  std::multimap<const base::FilePath, const base::FilePath> result;

  // Multiple sources, some of which multi-targeted
  const std::string prefix_1("/home/.shadow/");
  const std::multimap<const base::FilePath, const base::FilePath>
      expected_mounts_1{
          {kSource1, kTarget0},
          {kSource1, kTarget1},
          {kSource2, kTarget2},
          {kSource3, kTarget3},
      };
  fake_mapper_->ListMountsBySourcePrefix(prefix_1, &result);
  EXPECT_THAT(result, UnorderedElementsAreArray(expected_mounts_1));

  // Multiple sources, some of which multi-targeted, but on a partial path
  const std::string prefix_2("/home/.shadow/00");
  const std::multimap<const base::FilePath, const base::FilePath>
      expected_mounts_2{
          {kSource1, kTarget0},
          {kSource1, kTarget1},
          {kSource2, kTarget2},
      };
  fake_mapper_->ListMountsBySourcePrefix(prefix_2, &result);
  EXPECT_THAT(result, UnorderedElementsAreArray(expected_mounts_2));

  // A prefix that doesn't match any sources
  const std::string prefix_3("/home/.shadow/1");
  const std::multimap<const base::FilePath, const base::FilePath>
      expected_mounts_3;
  fake_mapper_->ListMountsBySourcePrefix(prefix_3, &result);
  EXPECT_THAT(result, UnorderedElementsAreArray(expected_mounts_3));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget3));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

TEST_F(FakeMountMapperTest, ListMountsBySourcePrefix_Path) {
  // Mount
  ASSERT_TRUE(fake_mapper_->Mount(kSource1, kTarget0));
  ASSERT_TRUE(fake_mapper_->Bind(kSource1, kTarget1));
  ASSERT_TRUE(fake_mapper_->Bind(kSource2, kTarget2));
  ASSERT_TRUE(fake_mapper_->Mount(kSource3, kTarget3));
  ASSERT_TRUE(fake_mapper_->Mount(kTarget1, kTarget4));

  std::multimap<const base::FilePath, const base::FilePath> result;

  // Multiple sources, some of which multi-targeted
  const base::FilePath prefix_1("/home/.shadow/");
  const std::multimap<const base::FilePath, const base::FilePath>
      expected_mounts_1{
          {kSource1, kTarget0},
          {kSource1, kTarget1},
          {kSource2, kTarget2},
          {kSource3, kTarget3},
      };
  fake_mapper_->ListMountsBySourcePrefix(prefix_1, &result);
  EXPECT_THAT(result, UnorderedElementsAreArray(expected_mounts_1));

  // Prefix exactly matches the source
  const base::FilePath prefix_2(kTarget1);
  const std::multimap<const base::FilePath, const base::FilePath>
      expected_mounts_2{
          {kTarget1, kTarget4},
      };
  fake_mapper_->ListMountsBySourcePrefix(prefix_2, &result);
  EXPECT_THAT(result, UnorderedElementsAreArray(expected_mounts_2));

  // Not a source for mount
  const base::FilePath prefix_3("/var/log");
  const std::multimap<const base::FilePath, const base::FilePath>
      expected_mounts_3;
  fake_mapper_->ListMountsBySourcePrefix(prefix_3, &result);
  EXPECT_THAT(result, UnorderedElementsAreArray(expected_mounts_3));

  // Unmount
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget4));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget3));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget2));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget1));
  ASSERT_TRUE(fake_mapper_->Unmount(kTarget0));
}

}  // namespace

}  // namespace cryptohome
