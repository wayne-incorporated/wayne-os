// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <arpa/inet.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/strings/utf_string_conversion_utils.h>

#include "vm_tools/garcon/mime_types_parser.h"

namespace {
// Ridiculously large size for a /usr/share/mime/mime.cache file.
// Default file is about 100KB, we will allow up to 10MB.
constexpr size_t kMaxMimeTypesFileSize = 10485760;
// Maximum number of nodes to allow in reverse suffix tree.
// Default file has ~3K nodes, we will allow up to 30K.
constexpr size_t kMaxNodes = 30000;
// Maximum file extension size.
constexpr size_t kMaxExtSize = 100;
// Header size in mime.cache file.
constexpr size_t kHeaderSize = 40;
// Largest valid unicode code point is U+10ffff.
constexpr uint32_t kMaxUnicode = 0x10ffff;

// Read 4 bytes from string |buf| at |offset| as network order uint32_t.
// Returns false if |offset > buf.size() - 4| or |offset| is not aligned to a
// 4-byte word boundary, or |*result| is not between |min_result| and
// |max_result|. |field_name| is used in error message.
bool ReadInt(std::string buf,
             uint32_t offset,
             std::string field_name,
             uint32_t min_result,
             uint32_t max_result,
             uint32_t* result) {
  if (offset > buf.size() - 4 || (offset & 0x3)) {
    LOG(ERROR) << "Invalid offset=" << offset << " for " << field_name
               << ", string size=" << buf.size();
    return false;
  }
  *result = ntohl(*reinterpret_cast<const uint32_t*>(buf.c_str() + offset));
  if (*result < min_result || *result > max_result) {
    LOG(ERROR) << "Invalid " << field_name << "=" << *result
               << " not between min_result=" << min_result
               << " and max_result=" << max_result;
    return false;
  }
  return true;
}

}  // namespace

namespace vm_tools {
namespace garcon {

bool ParseMimeTypes(const std::string& file_name, MimeTypeMap* out_mime_types) {
  CHECK(out_mime_types);
  base::FilePath file_path(file_name);
  if (!base::PathExists(file_path)) {
    VLOG(1) << "MIME types file does not exist at: " << file_name;
    return false;
  }

  // File format from
  // https://specifications.freedesktop.org/shared-mime-info-spec/shared-mime-info-spec-0.21.html#idm46070612075440
  // Header:
  // 2      CARD16    MAJOR_VERSION  1
  // 2      CARD16    MINOR_VERSION  2
  // 4      CARD32    ALIAS_LIST_OFFSET
  // 4      CARD32    PARENT_LIST_OFFSET
  // 4      CARD32    LITERAL_LIST_OFFSET
  // 4      CARD32    REVERSE_SUFFIX_TREE_OFFSET
  // ...
  // ReverseSuffixTree:
  // 4      CARD32    N_ROOTS
  // 4       CARD32    FIRST_ROOT_OFFSET
  // ReverseSuffixTreeNode:
  // 4      CARD32    CHARACTER
  // 4      CARD32    N_CHILDREN
  // 4      CARD32    FIRST_CHILD_OFFSET
  // ReverseSuffixTreeLeafNode:
  // 4      CARD32    0
  // 4      CARD32    MIME_TYPE_OFFSET
  // 4      CARD32    WEIGHT in lower 8 bits
  //                  FLAGS in rest:
  //                  0x100 = case-sensitive

  std::string buf;
  if (!base::ReadFileToStringWithMaxSize(file_path, &buf,
                                         kMaxMimeTypesFileSize)) {
    LOG(ERROR) << "Failed reading in mime.cache file: " << file_name;
    return false;
  }

  if (buf.size() < kHeaderSize) {
    LOG(ERROR) << "Invalid mime.cache file size=" << buf.size();
    return false;
  }

  // Validate file[ALIAS_LIST_OFFSET - 1] is null to ensure that any
  // null-terminated strings we dereference at addresses below ALIAS_LIST_OFFSET
  // will not overflow.
  uint32_t alias_list_offset = 0;
  if (!ReadInt(buf, 4, "ALIAS_LIST_OFFSET", kHeaderSize, buf.size(),
               &alias_list_offset)) {
    return false;
  }
  if (buf[alias_list_offset - 1] != 0) {
    LOG(ERROR) << "Invalid mime.cache file does not contain null prior to "
                  "ALIAS_LIST_OFFSET="
               << alias_list_offset;
    return false;
  }

  // Parse ReverseSuffixTree. We will read all nodes and place them on |stack|,
  // allowing max of kMaxNodes and max extension of kMaxExtSize.
  uint32_t tree_offset = 0;
  if (!ReadInt(buf, 16, "REVERSE_SUFFIX_TREE_OFFSET", kHeaderSize, buf.size(),
               &tree_offset)) {
    return false;
  }

  struct Node {
    std::string ext;
    uint32_t n_children;
    uint32_t first_child_offset;
  };

  // Read root node and put it on the stack.
  Node root;
  if (!ReadInt(buf, tree_offset, "N_ROOTS", 0, kMaxUnicode, &root.n_children)) {
    return false;
  }
  if (!ReadInt(buf, tree_offset + 4, "FIRST_ROOT_OFFSET", tree_offset,
               buf.size(), &root.first_child_offset)) {
    return false;
  }
  std::vector<Node> stack;
  stack.push_back(std::move(root));

  struct WeightedMime {
    std::string mime_type;
    uint8_t weight;
  };
  std::map<std::string, WeightedMime> types;
  uint32_t num_nodes = 0;
  while (stack.size() > 0) {
    // Pop top node from the stack and process children.
    Node n = stack.back();
    stack.pop_back();
    uint32_t p = n.first_child_offset;
    for (uint32_t i = 0; i < n.n_children; i++) {
      uint32_t c = 0;
      if (!ReadInt(buf, p, "CHARACTER", 0, kMaxUnicode, &c)) {
        return false;
      }
      p += 4;

      // Leaf node, add mime type if it is highest weight.
      if (c == 0) {
        uint32_t mime_type_offset = 0;
        if (!ReadInt(buf, p, "mime type offset", kHeaderSize,
                     alias_list_offset - 1, &mime_type_offset)) {
          return false;
        }
        p += 4;
        uint8_t weight = 50;
        if ((p + 3) < buf.size()) {
          weight = buf[p + 3];
        }
        p += 4;
        if (n.ext.size() == 0 || n.ext[0] != '.') {
          LOG(INFO) << "Ignoring extension without leading dot " << n.ext;
        } else {
          std::string ext = n.ext.substr(1);
          auto it = types.find(ext);
          if (it == types.end() || weight > it->second.weight) {
            types[ext] = {std::string(buf.c_str() + mime_type_offset), weight};
          }
        }
        continue;
      }

      // Regular node, parse and add it to the stack.
      Node node;
      base::WriteUnicodeCharacter(c, &node.ext);
      node.ext += n.ext;
      if (!ReadInt(buf, p, "N_CHILDREN", 0, kMaxUnicode, &node.n_children)) {
        return false;
      }
      p += 4;
      if (!ReadInt(buf, p, "FIRST_CHILD_OFFSET", tree_offset, buf.size(),
                   &node.first_child_offset)) {
        return false;
      }
      p += 4;

      // Check limits.
      if (++num_nodes > kMaxNodes) {
        LOG(ERROR) << "Exceeded maxium number of nodes=" << kMaxNodes;
        return false;
      }
      if (node.ext.size() > kMaxExtSize) {
        LOG(WARNING) << "Ignoring large extension exceeds size=" << kMaxExtSize
                     << " ext=" << node.ext;
      } else {
        stack.push_back(std::move(node));
      }
    }
  }

  for (auto const& item : types) {
    (*out_mime_types)[item.first] = item.second.mime_type;
  }
  return true;
}

}  // namespace garcon
}  // namespace vm_tools
