// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_SIGN_IN_HASH_TREE_H_
#define CRYPTOHOME_SIGN_IN_HASH_TREE_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/memory_mapped_file.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <gtest/gtest_prod.h>

#include "cryptohome/persistent_lookup_table.h"

namespace cryptohome {

inline constexpr char kLeafCacheFileName[] = "leafcache";

// This class represents the hash tree which is used to store and manage the
// various credentials used to access the system. It is used to represent
// not just the leaf nodes of the hash tree, but also hashes of the inner nodes.
//
// A hash tree is used because it offers an efficient way to store a large set
// of credentials and check the integrity of the stored data. This is
// accomplished by having each of the credentials occupy a leaf node. Each
// credential will have an HMAC associated with it, which is calculated on the
// credential metadata. Based on the fan-out, i.e number of children per node of
// the tree, the leaf nodes will be used to calculate the hash of their
// corresponding parent. This process will repeat until we find the hash of the
// root node.
//
// This hash will then be compared to the root hash value stored in a secure
// non-volatile storage ( e.g Cr50 ), and can be used to verify integrity of the
// data we have on disk.
//
// There are two variables which will define the structure of the hash-table:
// - The length of a leaf bit string, leaf_length.
// - The fan-out, i.e number of children for a parent, fan_out.
//
// leaf_length and fan_out are expected to obey the following relation:
//  leaf_length = n * log2(fan_out), where n is any non-negative integer.
//
// The recalculation of the entire hash tree given the leaf nodes can be
// time consuming. To avoid that, this class also maintains a "HashCache".
// Conceptually, the HashCache stores the hashes of each node of the hash
// tree for easy access without the need to recompute them on every operation.
// Practically, it is implemented in two parts:
// - LeafCache: This file will store the MACs of all the leaf nodes of the
//   hash tree. It is expected to persist across reboots, and will be accessible
//   via a memory mapped file descriptor. The LeafCache avoids having to read
//   all the leaves from disk to obtain their hashes, which would be slow.
// - InnerHashArray: This in-memory array will store the hashes of all the inner
//   nodes of the hash tree. It is expected to be regenerated on the first
//   operation after a reboot. When a SignInHashTree object is created, the
//   InnerHashArray will consist of an all-zero array. This can be used to
//   determine whether the InnerHashArray has been initialized or not.
//
// Once the HashCache is generated, we can index into the file or array to find
// the relevant node's hash. NOTE: The HashCache is considered to be completely
// redundant. If there is any detected discrepancy between the root hash on the
// InnerHashArray, and the root hash on the Cr50, we will reconstruct the
// HashCache from scratch.
//
// While calculating the inner nodes' hashes, the LeafCache will be used to
// get the corresponding leaf MAC values.
//
// The SignInHashTree needs a persistent consistent storage on disk, and this
// will be provided by the PersistentLookupTable (referred to as PLT in the
// comments for this class, due to brevity).
//
// For each label, the value stored in the PersistentLookupTable will be in
// the following format
//
// |   HMAC(credential meatadata)   |             credential metadata          |
// |                                |                                          |
//
// Empty or non-existent leaf labels are assumed to have an HMAC of 32 bytes of
// zeroes.
class SignInHashTree {
 public:
  static constexpr size_t kHashSize = 32;

  // Convenience class to help represent the labels of nodes in the
  // SignInHashTree.
  // The high level abstraction is one of a bitstring. This can be
  // realized by using:
  // - a uin64_t |value_| variable, which can represent a bitstring of max
  // length 64.
  // - a |length| variable, which denotes the length of the bitstring
  // stored in the |value_| variable.
  //
  // In addition, we also store the number of bits per level of the
  // hash tree, represented by |bits_per_level_|. This variable
  // helps to both obtain the parent of a label, and to create children
  // for a particular label.
  class Label {
   public:
    Label() = default;
    Label(uint64_t value, uint8_t length, uint8_t bits_per_level)
        : value_(value), length_(length), bits_per_level_(bits_per_level) {
      CHECK_LE(length, 64);
      CHECK_EQ(0, length % bits_per_level);
    }

    uint64_t value() const { return value_; }

    uint8_t length() const { return length_; }

    bool is_root() const { return length_ == 0; }

    // Helper function to map the label to a unique non-negative index. The
    // index is the position of the tree node in pre-order traversal.
    // This can be used to index arrays with each array element
    // corresponding to a specific tree node.
    uint32_t cache_index() const {
      uint8_t height = length_ / bits_per_level_;
      uint8_t fan_out = 1 << bits_per_level_;

      // The the starting index for a height H in the hash tree is computed
      // as follows:
      //   starting_index(H) = starting_index(H-1) + fan_out^(H-1)
      //
      // This is geometric series which can be collapsed into the closed
      // form expression:
      //  starting_index(H) = (starting_index^(H + 1) - 1) / (fan_out - 1)
      //
      // |value_| is added to the starting index to get the cache index.
      uint32_t starting_index =
          ((1 << (bits_per_level_ * height)) - 1) / (fan_out - 1);
      return starting_index + value_;
    }

    // This function returns a Label which denotes the parent of Label
    // itself.
    Label GetParent() const {
      CHECK_GT(length_, 0);
      uint64_t parent_value = value_ >> bits_per_level_;
      uint8_t parent_length = length_ - bits_per_level_;
      return Label(parent_value, parent_length, bits_per_level_);
    }

    // This function helps to generate a child label of the current label,
    // appended with the child label suffix denoted by |child|.
    Label Extend(uint64_t child) const {
      uint8_t child_length = length_ + bits_per_level_;
      CHECK_LE(child_length, 64);
      CHECK_EQ(0, child & ~((1 << bits_per_level_) - 1));
      uint64_t child_value = value_ << bits_per_level_ | child;
      return Label(child_value, child_length, bits_per_level_);
    }

    bool operator!=(const Label& rhs) const {
      return value_ != rhs.value_ || length_ != rhs.length_ ||
             bits_per_level_ != rhs.bits_per_level_;
    }

    // If |bits_per_level_| is zero, the Label is considered invalid.
    bool is_valid() const { return bits_per_level_ != 0; }

   private:
    uint64_t value_ = 0;
    uint8_t length_ = 0;
    uint8_t bits_per_level_ = 0;
  };

  SignInHashTree(uint32_t leaf_length,
                 uint8_t bits_per_level,
                 base::FilePath basedir);

  ~SignInHashTree();

  bool IsValid();

  // Return a vector of labels required to recompute the root node hash,
  // given the leaf node label |key|. This function will return a list
  // of relevant labels on success, and an empty list otherwise.
  //
  // NOTE: The list of auxiliary labels returned will follow a specific
  // order (left-to-right, bottom to top). That way, we can reason about
  // which hashes to use for which specific inner node hash calculation when
  // coupled with knowledge of the credential label in question.
  std::vector<Label> GetAuxiliaryLabels(const Label& leaf_label);

  // Compute all the hashes of the hash tree.
  //
  // This function first calls PopulateLeafCache(), and then calculates all
  // inner hashes and updates the |inner_hash_array_|.
  void GenerateAndStoreHashCache();

  // Compute all the inner hashes of the hash tree (i.e all levels of the hash
  // tree except for the leaf level). This function calls CalculateHash() on the
  // root hash.
  void GenerateInnerHashArray();

  // Store the credential data for label |label| in the Hash Tree.
  // The HMAC and the credential metadata are provided as two parameters,
  // |hmac| and |cred_data| respectively.
  // In case the label is an inner node , |hmac| will represent the hash of the
  // node, and |cred_data| MUST be empty. |metadata_lost| signifies whether
  // there is valid metadata stored for this label(false) or not(true).
  // This function should lead to two things happening(in the prescribed order):
  // - Concat the HMAC and credential metadata blobs together and store it
  //   in the underlying PersistentLookupTable pointed by |plt_|, with the
  //   key |label.value()|.
  // - Store the MAC in the |leaf_cache_| file if it is a leaf label, or update
  //   the |inner_hash_array_| otherwise.
  // - This function will also update the HashCache (i.e all the hashes along
  //   the path to the root hash) as well.
  //
  // NOTE: The SignInHashTree will write over any previous value for a
  // particular label. Ensure that the label is available before invoking this
  // routine. To obtain available labels, use SignInHashTree::GetFreeLabel().
  //
  // TODO(pmalani): Split into CreateLabel() and UpdateLabel() to better
  // clarify the user intention.
  [[nodiscard]] bool StoreLabel(const Label& label,
                                const std::vector<uint8_t>& hmac,
                                const std::vector<uint8_t>& cred_metadata,
                                bool metadata_lost);

  // Get the hash/hmac and, if applicable, the credential metadata associated
  // with a label.
  // If |label| refers to a leaf node, then |cred_data| will be filled to
  // contain the relevant credential metadata, and |hmac| will be filled with
  // the associated HMAC, which will be taken directly from the table.
  // If |label| refers to an inner node, then the |hmac| will be filled with the
  // hash obtained from the |inner_hash_array_|.
  //
  // |hmac| and |cred_data| are expected to be pointers to empty vectors. The
  // function will ensure that the corresponding vectors have sufficient space.
  // |metadata_lost| will return whether the credential metadata in this leaf
  // is lost or not. This flag is set to true when a leaf was re-inserted as
  // part of a log replay operation.
  //
  // Note that the hash returned may be incorrect if the HashCache is stale
  // or erroneous, and a failure will necessitate the regeneration of the
  // HashCache.
  //
  // Note that this function does NOT update the |leaf_cache_|. Therefore, in
  // the event that the |leaf_cache_| is inconsistent with the on-disk table
  // contents, the values retrieved from GetLabelData() and |leaf_cache_| may
  // be different.
  //
  // Returns true on success, false otherwise.
  [[nodiscard]] bool GetLabelData(const Label& label,
                                  std::vector<uint8_t>* hmac,
                                  std::vector<uint8_t>* cred_metadata,
                                  bool* metadata_lost);

  // Remove the credential metadata associated with label |label| from the hash
  // tree. The |label| must refer to a leaf node; if a label for a inner node is
  // provided, or if the underlying PLT has an issue, an error will be returned.
  //
  // The function will update the HashCache after removing the label.
  //
  // Returns true on success, false otherwise.
  [[nodiscard]] bool RemoveLabel(const Label& label);

  // Returns the first available free leaf label for credential metadata.
  // Returns the label on success. If a free label is not available, this
  // function will return an empty Label (i.e value_ = length_ =
  // bits_per_per_level_ = 0);
  Label GetFreeLabel();

  // Fills the current root hash from |inner_hash_array_| into
  // |root_hash|. Before that, it regenerates the entire |inner_hash_array_|.
  void GetRootHash(std::vector<uint8_t>* root_hash);

 private:
  // Recursive function which is used to calculate the hashes for the hash tree,
  // starting node |label|. The resultant hash is returned.
  // This function assumes that the leaf MAC values have already been updated
  // in the |leaf_cache_|.
  //
  // In addition to calculating the hash for |label|, this function will
  // also update the |inner_hash_array_| with the new value.
  std::vector<uint8_t> CalculateHash(const Label& label);

  // Helper function to determine whether a Label corresponds to a leaf
  // node of the hash tree.
  bool IsLeafLabel(const Label& l) { return l.length() == leaf_length_; }

  // Update the HashCache associated with the path for |label|, and in doing
  // so modifies the |inner_hash_array_|.
  // This function is typically called after an update is made to the
  // underlying PLT.
  // This function assumes that the |leaf_cache_| is up to date,
  void UpdateHashCacheLabelPath(const Label& label);

  // Update the |inner_hash_array_| with the provided value.
  // This function does NOT update the entire HashCache label path to the root
  // for this index.
  void UpdateInnerHashArray(uint32_t index, const uint8_t* data, size_t size);

  // Update the |leaf_cache_| with the provided value.
  // This function does NOT update the entire HashCache label path to the root
  // for this index.
  void UpdateLeafCache(uint32_t index, const uint8_t* data, size_t size);

  // Populate the |leaf_cache_| with the MAC values of all leaf labels.
  void PopulateLeafCache();

  bool is_valid_;
  // Length of the leaf node label.
  uint32_t leaf_length_;
  // Fan out of the hash tree, i.e number of children of each inner node.
  uint32_t fan_out_;
  // Number of bits per level of the hash tree.
  uint8_t bits_per_level_;
  // Memory mapped file pointing to the LeafCache file on disk.
  base::MemoryMappedFile leaf_cache_;
  // Pointer to the |leaf_cache_| file data.
  // Each element is a 32-byte hash.
  uint8_t (*leaf_cache_array_)[kHashSize];
  // In-memory array used to store inner node hash values.
  std::vector<uint8_t> inner_hash_vector_;
  // Pointer to the |inner_hash_vector_| data.
  uint8_t (*inner_hash_array_)[kHashSize];

  // This is used to actually store and retrieve data from the backing disk
  // storage.
  std::unique_ptr<Platform> p_;
  PersistentLookupTable plt_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_SIGN_IN_HASH_TREE_H_
