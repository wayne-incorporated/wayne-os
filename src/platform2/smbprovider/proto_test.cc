// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <dbus/smbprovider/dbus-constants.h>
#include <gtest/gtest.h>

#include "smbprovider/constants.h"
#include "smbprovider/proto.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"
#include "smbprovider/smbprovider_helper.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {
namespace {

template <typename Proto>
void CheckMethodName(const char* name, const Proto& proto) {
  EXPECT_EQ(0, strcmp(name, GetMethodName(proto)));
}

void CheckDirectoryEntryAndDirectoryEntryProtoAreEqual(
    const DirectoryEntry& entry, const DirectoryEntryProto& proto) {
  EXPECT_EQ(entry.is_directory, proto.is_directory());
  EXPECT_EQ(entry.name, proto.name());
  EXPECT_EQ(entry.size, proto.size());
  EXPECT_EQ(entry.last_modified_time, proto.last_modified_time());
}

}  // namespace

class SmbProviderProtoTest : public testing::Test {
 public:
  SmbProviderProtoTest() = default;
  SmbProviderProtoTest(const SmbProviderProtoTest&) = delete;
  SmbProviderProtoTest& operator=(const SmbProviderProtoTest&) = delete;

  ~SmbProviderProtoTest() override = default;
};

// Blobs should be serialized correctly.
TEST_F(SmbProviderProtoTest, SerializeProtoToBlob) {
  DirectoryEntryProto entry;
  entry.set_is_directory(true);
  entry.set_name("test");
  entry.set_size(0);
  entry.set_last_modified_time(0);

  ProtoBlob blob;

  EXPECT_EQ(ERROR_OK, SerializeProtoToBlob(entry, &blob));
}

// DirectoryEntryCtor initializes a DirectoryEntry correctly.
TEST_F(SmbProviderProtoTest, DirectoryEntry) {
  const bool is_dir = false;
  const std::string name = "testentry.jpg";
  const std::string full_path = "smb://testUrl/testentry.jpg";
  int64_t size = 23;
  int64_t last_modified_time = 456;
  DirectoryEntry entry(is_dir, name, full_path, size, last_modified_time);

  EXPECT_EQ(is_dir, entry.is_directory);
  EXPECT_EQ(name, entry.name);
  EXPECT_EQ(full_path, entry.full_path);
  EXPECT_EQ(size, entry.size);
  EXPECT_EQ(last_modified_time, entry.last_modified_time);
}

// ConvertToProto correctly converts a DirectoryEntry to a DirectoryEntryProto.
TEST_F(SmbProviderProtoTest, ConvertToProto) {
  DirectoryEntry entry(false /* is_directory */, "testentry.jpg",
                       "smb://testUrl/testentry.jpg", 23 /* size */,
                       456 /* last_modified_time */);

  DirectoryEntryProto proto;
  ConvertToProto(entry, &proto);

  CheckDirectoryEntryAndDirectoryEntryProtoAreEqual(entry, proto);
}

// AddDirectoryEntry adds a DirectoryEntry to a DirectoryEntryListProto as a
// DirectoryEntryProto.
TEST_F(SmbProviderProtoTest, AddDirectoryEntry) {
  DirectoryEntry entry(false /* is_directory */, "testentry.jpg",
                       "smb://testUrl/testentry.jpg", 23 /* size */,
                       456 /* last_modified_time */);

  DirectoryEntryListProto entries_proto;

  EXPECT_EQ(0, entries_proto.entries_size());
  AddDirectoryEntry(entry, &entries_proto);
  EXPECT_EQ(1, entries_proto.entries_size());

  DirectoryEntryProto entry_proto = entries_proto.entries(0);
  CheckDirectoryEntryAndDirectoryEntryProtoAreEqual(entry, entry_proto);
}

// SerializeDirEntryVectorToProto correctly serializes a vector of dirents.
TEST_F(SmbProviderProtoTest, SerializeDirEntryVectorToProto) {
  std::vector<DirectoryEntry> entries;
  DirectoryEntry entry1(false /* is_directory */, "testentry.jpg",
                        "smb://testUrl/testentry.jpg", 23 /* size */,
                        456 /* last_modified_time */);
  DirectoryEntry entry2(true /* is_directory */, "stuff",
                        "smb://testUrl/testentry.jpg", 5 /* size */,
                        789 /* last_modified_time */);
  entries.push_back(entry1);
  entries.push_back(entry2);

  DirectoryEntryListProto entries_proto;
  SerializeDirEntryVectorToProto(entries, &entries_proto);

  EXPECT_EQ(2, entries_proto.entries_size());
  CheckDirectoryEntryAndDirectoryEntryProtoAreEqual(entry1,
                                                    entries_proto.entries(0));
  CheckDirectoryEntryAndDirectoryEntryProtoAreEqual(entry2,
                                                    entries_proto.entries(1));
}

}  // namespace smbprovider
