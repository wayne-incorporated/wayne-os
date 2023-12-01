// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/recursive_delete_operation.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback_helpers.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "smbfs/samba_interface_impl.h"
#include "smbfs/smb_credential.h"
#include "smbfs/smb_filesystem.h"

namespace smbfs {
namespace {

using ::testing::_;
using ::testing::Return;

constexpr char kSharePath[] = "smb://server/share";
constexpr char kDirectoryToDelete[] = "/the/directory";
constexpr char kFileToDelete[] = "/the/directory/file";

class MockSmbFilesystemDelegate : public SmbFilesystem::Delegate {
 public:
  MOCK_METHOD(void,
              RequestCredentials,
              (RequestCredentialsCallback),
              (override));
};

class MockSambaInterface : public SambaInterfaceImpl {
 public:
  MOCK_METHOD(int, UnlinkFile, (const std::string&), (override));
  MOCK_METHOD(int, RemoveDirectory, (const std::string&), (override));
  MOCK_METHOD(int, CloseDirectory, (SMBCFILE*), (override));
  MOCK_METHOD(int, OpenDirectory, (const std::string&, SMBCFILE**), (override));
  MOCK_METHOD(int,
              ReadDirectory,
              (SMBCFILE*, const struct libsmb_file_info**, struct stat*),
              (override));
};

class MockSmbFilesystem : public SmbFilesystem {
 public:
  MockSmbFilesystem()
      : SmbFilesystem(&mock_delegate_, kSharePath),
        mock_samba_impl_(new MockSambaInterface()) {
    const std::vector<uint8_t> empty_ip_address;
    SetResolvedAddress(empty_ip_address);
    SetSambaInterface(std::unique_ptr<SambaInterface>(mock_samba_impl_));
  }

  MockSambaInterface* samba_impl() { return mock_samba_impl_; }

 private:
  MockSmbFilesystemDelegate mock_delegate_;
  MockSambaInterface* mock_samba_impl_;
};

class TestRecursiveDeleteOperation : public RecursiveDeleteOperation {
 public:
  explicit TestRecursiveDeleteOperation(CompletionCallback callback)
      : RecursiveDeleteOperation(nullptr,
                                 kSharePath,
                                 base::FilePath(kDirectoryToDelete),
                                 std::move(callback)) {
    SetSambaInterface(fs_.samba_impl());
  }

  MockSmbFilesystem& fs() { return fs_; }

 private:
  MockSmbFilesystem fs_;
};

}  // namespace

class RecursiveDeleteOperationTest : public testing::Test {
 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
};

TEST_F(RecursiveDeleteOperationTest, DeleteFile) {
  TestRecursiveDeleteOperation delete_operation((base::DoNothing()));

  base::FilePath file_path(kFileToDelete);
  std::string share_path = std::string(kSharePath) + file_path.value();

  EXPECT_CALL(*(delete_operation.fs().samba_impl()), UnlinkFile(_))
      .WillOnce([&](const std::string& share_file_path) -> int {
        EXPECT_EQ(share_path, share_file_path);
        return 0;
      });
  delete_operation.DeleteFile(file_path);
}

TEST_F(RecursiveDeleteOperationTest, DeleteDirectory) {
  TestRecursiveDeleteOperation delete_operation(
      base::BindOnce([](mojom::DeleteRecursivelyError error) {}));

  base::FilePath dir_path(kDirectoryToDelete);
  std::string share_path = std::string(kSharePath) + dir_path.value();

  EXPECT_CALL(*(delete_operation.fs().samba_impl()), RemoveDirectory(_))
      .WillOnce([&](const std::string& share_dir_path) -> int {
        EXPECT_EQ(share_path, share_dir_path);
        return 0;
      });
  delete_operation.DeleteDirectory(dir_path);
}

TEST_F(RecursiveDeleteOperationTest, CloseDirectory) {
  TestRecursiveDeleteOperation delete_operation(
      base::BindOnce([](mojom::DeleteRecursivelyError error) {}));

  EXPECT_CALL(*(delete_operation.fs().samba_impl()), CloseDirectory(_))
      .WillOnce([&](SMBCFILE* dir) -> int { return 0; });
  delete_operation.CloseDirectory(nullptr);
}

TEST_F(RecursiveDeleteOperationTest, GetDirectoryListing) {
  TestRecursiveDeleteOperation delete_operation(
      base::BindOnce([](mojom::DeleteRecursivelyError error) {}));

  EXPECT_CALL(*(delete_operation.fs().samba_impl()), OpenDirectory(_, _))
      .Times(1)
      .WillOnce(Return(0));
  EXPECT_CALL(*(delete_operation.fs().samba_impl()), CloseDirectory(_))
      .Times(1)
      .WillOnce(Return(0));

  // Mock out the listing of a directory with two entries: a file and a
  // subdirectory.
  struct MockEntry {
    std::string entry_name;
    struct libsmb_file_info entry_info;
    struct stat entry_stat;
  };

  int entry_count = 0;
  std::vector<MockEntry> mock_entries = {{"file_name", {0}, {0}},
                                         {"dir_name", {0}, {0}}};
  mock_entries[1].entry_stat.st_mode |= S_IFDIR;

  EXPECT_CALL(*(delete_operation.fs().samba_impl()), ReadDirectory(_, _, _))
      .Times(mock_entries.size() + 1)
      .WillRepeatedly([&](SMBCFILE* dir,
                          const struct libsmb_file_info** file_info,
                          struct stat* file_stat) -> int {
        if (entry_count < mock_entries.size()) {
          *file_info = &(mock_entries[entry_count].entry_info);
          struct libsmb_file_info** inner_file_info =
              const_cast<struct libsmb_file_info**>(file_info);
          (*inner_file_info)->name =
              const_cast<char*>(mock_entries[entry_count].entry_name.c_str());
          *file_stat = mock_entries[entry_count].entry_stat;
        } else {
          *file_info = nullptr;
        }

        entry_count++;
        return 0;
      });

  base::FilePath dir_path(kDirectoryToDelete);
  std::list<struct RecursiveDeleteOperation::Entry> entries;
  bool success = delete_operation.GetDirectoryListing(dir_path, &entries);
  EXPECT_TRUE(success);

  EXPECT_EQ(mock_entries.size(), entries.size());

  RecursiveDeleteOperation::Entry entry = entries.front();
  EXPECT_EQ(entry.path, dir_path.Append(mock_entries[0].entry_name));
  EXPECT_FALSE(entry.is_directory);

  entries.pop_front();
  entry = entries.front();
  EXPECT_EQ(entry.path.value(),
            dir_path.Append(mock_entries[1].entry_name).value());
  EXPECT_TRUE(entry.is_directory);
}

}  // namespace smbfs
