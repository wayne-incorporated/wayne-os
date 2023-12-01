// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <gtest/gtest.h>

#include <base/check_op.h>
#include <base/files/scoped_temp_dir.h>
#include <base/files/file_util.h>
#include <base/files/file_path.h>

#include "ureadahead-diff/ureadahead_diff.h"

namespace ureadahead_diff {

namespace {

// Adds test file to pack from read requests as pairs of page offset and page
// count.
void AddFileToPack(Pack* pack,
                   const std::string& path,
                   const std::vector<std::pair<int, int>> read_requests) {
  PackPath pack_path;
  pack_path.group = -1;
  pack_path.ino = 0;
  DCHECK_GT(PACK_PATH_MAX - 1, path.length());
  snprintf(pack_path.path, PACK_PATH_MAX - 1, "%s", path.c_str());

  std::unique_ptr<FileEntry> file = std::make_unique<FileEntry>(pack_path);

  std::vector<PackBlock> pack_blocks;

  PackBlock pack_block;
  pack_block.pathidx = pack->GetFileCount();
  pack_block.physical = -1;

  const size_t page_size = sysconf(_SC_PAGESIZE);

  for (const auto& read_request : read_requests) {
    pack_block.offset = read_request.first * page_size;
    pack_block.length = read_request.second * page_size;
    pack_blocks.emplace_back(pack_block);
  }

  file->BuildFromReadRequests(pack_blocks);
  pack->AddFile(std::move(file));
}

bool PacksMatch(Pack* pack1, Pack* pack2) {
  if (pack1->GetFileCount() != pack2->GetFileCount())
    return false;

  for (size_t i = 0; i < pack1->GetFileCount(); ++i) {
    FileEntry* const file1 = pack1->GetFile(i);
    FileEntry* const file2 = pack2->GetFile(i);

    if (file1->pack_path() != file2->pack_path())
      return false;

    const std::vector<PackBlock> requests1 =
        file1->GetReadRequests(i /* pathidx */);
    const std::vector<PackBlock> requests2 =
        file2->GetReadRequests(i /* pathidx */);
    if (requests1 != requests2)
      return false;
  }

  return true;
}

}  // namespace

TEST(Pack, Basic) {
  constexpr char kUniquePath[] = "unique";
  constexpr char kEqualPath[] = "equal";
  constexpr char kOverlapPath[] = "overlap";
  constexpr char kInclusionPath[] = "inclusion";
  constexpr char kNonIntersectPath[] = "non-intersect";

  Pack pack1;
  Pack pack2;

  AddFileToPack(&pack1, kUniquePath, {{1, 2}});

  AddFileToPack(&pack1, kEqualPath, {{3, 2}});
  AddFileToPack(&pack2, kEqualPath, {{3, 2}});

  AddFileToPack(&pack1, kOverlapPath, {{2, 3}});
  AddFileToPack(&pack2, kOverlapPath, {{4, 2}});

  AddFileToPack(&pack1, kInclusionPath, {{5, 5}});
  AddFileToPack(&pack2, kInclusionPath, {{6, 3}});

  AddFileToPack(&pack1, kNonIntersectPath, {{5, 3}});
  AddFileToPack(&pack2, kNonIntersectPath, {{1, 4}});

  Pack common;
  Pack::CalculateDifference(&pack1, &pack2, &common);

  // Create verification packs that should match what we calculated.
  Pack verify_common;
  AddFileToPack(&verify_common, kEqualPath, {{3, 2}});
  AddFileToPack(&verify_common, kOverlapPath, {{4, 1}});
  AddFileToPack(&verify_common, kInclusionPath, {{6, 3}});
  EXPECT_TRUE(PacksMatch(&common, &verify_common));

  Pack verify_pack1;
  AddFileToPack(&verify_pack1, kUniquePath, {{1, 2}});
  AddFileToPack(&verify_pack1, kOverlapPath, {{2, 2}});
  AddFileToPack(&verify_pack1, kInclusionPath, {{5, 1}, {9, 1}});
  AddFileToPack(&verify_pack1, kNonIntersectPath, {{5, 3}});
  EXPECT_TRUE(PacksMatch(&pack1, &verify_pack1));

  Pack verify_pack2;
  AddFileToPack(&verify_pack2, kOverlapPath, {{5, 1}});
  AddFileToPack(&verify_pack2, kNonIntersectPath, {{1, 4}});
  EXPECT_TRUE(PacksMatch(&pack2, &verify_pack2));
}

TEST(Pack, Serialize) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  const std::string pack_name = temp_directory.GetPath().Append("pack").value();

  Pack pack;
  AddFileToPack(&pack, "test1", {{1, 2}});
  AddFileToPack(&pack, "test2", {{1, 2}, {5, 3}, {10, 2}});
  AddFileToPack(&pack, "test3", {{0, 100}});
  EXPECT_TRUE(pack.Write(pack_name));

  Pack pack_read;
  EXPECT_TRUE(pack_read.Read(pack_name));
  EXPECT_TRUE(PacksMatch(&pack, &pack_read));
}

TEST(Pack, ReadRequests) {
  const size_t page_size = sysconf(_SC_PAGESIZE);

  Pack pack;
  // Requests are from the beginning, in the middle and till the end.
  AddFileToPack(&pack, "test1", {{0, 2}, {3, 3}, {7, 4}});

  // Request is not from the beginning.
  AddFileToPack(&pack, "test2", {{1, 2}});

  ASSERT_EQ(2U, pack.GetFileCount());

  const std::vector<PackBlock> blocks1 = pack.GetFile(0)->GetReadRequests(0);
  ASSERT_EQ(3U, blocks1.size());
  EXPECT_EQ(0 * page_size, blocks1[0].offset);
  EXPECT_EQ(2 * page_size, blocks1[0].length);
  EXPECT_EQ(3 * page_size, blocks1[1].offset);
  EXPECT_EQ(3 * page_size, blocks1[1].length);
  EXPECT_EQ(7 * page_size, blocks1[2].offset);
  EXPECT_EQ(4 * page_size, blocks1[2].length);

  const std::vector<PackBlock> blocks2 = pack.GetFile(1)->GetReadRequests(1);
  ASSERT_EQ(1U, blocks2.size());
  EXPECT_EQ(1 * page_size, blocks2[0].offset);
  EXPECT_EQ(2 * page_size, blocks2[0].length);
}

TEST(Pack, Trim) {
  Pack pack;
  AddFileToPack(&pack, "non-empty", {{5, 5}});
  AddFileToPack(&pack, "empty", {});

  EXPECT_EQ(2U, pack.GetFileCount());
  pack.TrimEmptyFiles();
  EXPECT_EQ(1U, pack.GetFileCount());
}

TEST(Pack, TrimOnCalculate) {
  constexpr char kInclusionPath[] = "inclusion";

  Pack pack1;
  Pack pack2;

  AddFileToPack(&pack1, kInclusionPath, {{5, 5}});
  AddFileToPack(&pack2, kInclusionPath, {{6, 3}});

  Pack common;
  // File entry from |pack2| will be trimmed.
  Pack::CalculateDifference(&pack1, &pack2, &common);

  ASSERT_EQ(1U, common.GetFileCount());
  ASSERT_EQ(1U, pack1.GetFileCount());
  EXPECT_EQ(0U, pack2.GetFileCount());

  EXPECT_FALSE(common.GetFile(0)->IsEmpty());
  EXPECT_FALSE(pack1.GetFile(0)->IsEmpty());
}

TEST(Pack, InvalidFile) {
  base::ScopedTempDir temp_directory;
  ASSERT_TRUE(temp_directory.CreateUniqueTempDir());

  const std::string pack_name = temp_directory.GetPath().Append("pack").value();

  // Create default valid file.
  Pack pack;
  AddFileToPack(&pack, "test1", {{1, 2}});
  EXPECT_TRUE(pack.Write(pack_name));

  const base::FilePath pack_path(pack_name);
  std::string content;
  EXPECT_TRUE(ReadFileToString(pack_path, &content));

  constexpr size_t header_size = 8;
  constexpr size_t dev_offset = header_size;
  constexpr size_t created_offset = dev_offset + sizeof(dev_t);
  constexpr size_t num_groups_offset = created_offset + sizeof(time_t);
  constexpr size_t num_paths_offset = num_groups_offset + sizeof(size_t);
  constexpr size_t paths_offset = num_paths_offset + sizeof(size_t);
  constexpr size_t num_blocks_offset = paths_offset + sizeof(PackPath);
  constexpr size_t blocks_offset = num_blocks_offset + sizeof(size_t);
  constexpr size_t end = blocks_offset + sizeof(PackBlock);

  ASSERT_EQ(end, content.size());

  std::string content_broken;

  // Corrupt signature.
  content_broken = content;
  content_broken[0] = 'x';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));

  // Fill reserved field.
  content_broken = content;
  content_broken[header_size - 1] = 'x';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));

  // Groups are not supported
  content_broken = content;
  content_broken[num_groups_offset] = '\1';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));

  // Path number mismatch
  content_broken = content;
  content_broken[num_paths_offset] = '\2';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));

  // Path is not 0 terminated string.
  content_broken = content;
  char* const path =
      (reinterpret_cast<PackPath*>(&content_broken[0] + paths_offset))->path;
  for (size_t i = 0; i <= PACK_PATH_MAX; ++i)
    path[i] = 'a';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));

  // Block number mismatch
  content_broken = content;
  content_broken[num_blocks_offset] = '\2';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));

  // Block's pathidx invalid
  content_broken = content;
  // pathidx is the first element in struct.
  content_broken[blocks_offset] = '\2';
  EXPECT_TRUE(
      base::WriteFile(pack_path, &content_broken[0], content_broken.length()));
  EXPECT_FALSE(pack.Read(pack_name));
}

}  // namespace ureadahead_diff
