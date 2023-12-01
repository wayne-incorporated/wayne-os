// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/sign_in_hash_tree.h"

#include <fcntl.h>

#include <algorithm>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>

#include "cryptohome/hash_tree_leaf_data.pb.h"

using ::hwsec_foundation::GetSecureRandom;
using ::hwsec_foundation::Sha256;

namespace cryptohome {

constexpr size_t SignInHashTree::kHashSize;

SignInHashTree::SignInHashTree(uint32_t leaf_length,
                               uint8_t bits_per_level,
                               base::FilePath basedir)
    : is_valid_(true),
      leaf_length_(leaf_length),
      fan_out_(1 << bits_per_level),
      bits_per_level_(bits_per_level),
      p_(new Platform()),
      plt_(p_.get(), basedir) {
  // leaf_length_ should be divisible by bits_per_level_.
  CHECK(!(leaf_length_ % bits_per_level_));

  // TODO(pmalani): This should not happen on cryptohomed restart.
  plt_.InitOnBoot();

  // The number of entries in the hash tree can be given by the geometric
  // series: For a height H, the number of entries in the hash tree can be given
  // by the relation:
  //   num_entries(H) = num_entries(H-1) + fan_out^(H-1)
  //
  // This can be collapsed into the closed form expression:
  // num_entries(H) = (fan_out^(H + 1) - 1) / (fan_out - 1)
  uint32_t height = leaf_length_ / bits_per_level_;
  // We use |height - 1| since we only want to store the inner hashes, not
  // the leaves.
  height -= 1;
  uint32_t num_entries =
      ((1 << (bits_per_level_ * (height + 1))) - 1) / (fan_out_ - 1);

  // Inner hash cache initialized to all 0's.
  inner_hash_vector_.assign(num_entries * kHashSize, 0);
  inner_hash_array_ =
      reinterpret_cast<decltype(inner_hash_array_)>(inner_hash_vector_.data());

  // Ensure a leaf cache file of the right size exists, so that we can mmap it
  // correctly later.
  base::FilePath leaf_cache_file = basedir.Append(kLeafCacheFileName);
  auto leaf_cache_fd = std::make_unique<base::ScopedFD>(open(
      leaf_cache_file.value().c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR));
  if (!leaf_cache_fd->is_valid()) {
    PLOG(ERROR) << "Failed to open the leaf_cache_file: "
                << leaf_cache_file.value();
    struct stat sb;
    if (stat(leaf_cache_file.value().c_str(), &sb) == -1) {
      PLOG(ERROR) << "Failed to stat the leaf_cache_file: "
                  << leaf_cache_file.value();
    } else {
      LOG(INFO) << "leaf_cache_file mode: "
                << base::StringPrintf("%03o", sb.st_mode);
    }
    is_valid_ = false;
    return;
  }
  CHECK(!ftruncate(leaf_cache_fd->get(), (1 << leaf_length_) * kHashSize));
  leaf_cache_fd.reset();

  CHECK(leaf_cache_.Initialize(leaf_cache_file,
                               base::MemoryMappedFile::READ_WRITE));
  leaf_cache_array_ =
      reinterpret_cast<decltype(leaf_cache_array_)>(leaf_cache_.data());
}

SignInHashTree::~SignInHashTree() {}

bool SignInHashTree::IsValid() {
  return is_valid_;
}

std::vector<SignInHashTree::Label> SignInHashTree::GetAuxiliaryLabels(
    const Label& leaf_label) {
  std::vector<Label> aux_labels;

  Label cur_label = leaf_label;
  while (!cur_label.is_root()) {
    Label parent = cur_label.GetParent();
    for (uint64_t i = 0; i < fan_out_; i++) {
      Label child = parent.Extend(i);
      if (child != cur_label) {
        aux_labels.push_back(child);
      }
    }
    cur_label = parent;
  }

  return aux_labels;
}

void SignInHashTree::PopulateLeafCache() {
  // Get all of the GetLabelData succeed before UpdateLeafCache.
  uint64_t num_max_labels = 1 << leaf_length_;
  std::vector<std::vector<uint8_t>> hmac_history;
  hmac_history.reserve(num_max_labels);
  for (uint64_t i = 0; i < num_max_labels; i++) {
    std::vector<uint8_t> hmac, cred_metadata;
    bool metadata_lost;
    Label label(i, leaf_length_, bits_per_level_);
    if (!GetLabelData(label, &hmac, &cred_metadata, &metadata_lost)) {
      LOG(ERROR) << "Error getting leaf HMAC, can't regenerate HashCache.";
      return;
    }
    // There may exist label that failed to get data in the later iterations
    // of this loop, write the label data into cache earlier would cause a
    // flakiness to the hash tree. Just put the hmac into a temporary vector
    // without direct writing to the cache here.
    hmac_history.push_back(std::move(hmac));
  }
  // Only write to the cache when every label is valid.
  for (uint64_t i = 0; i < num_max_labels; i++) {
    const std::vector<uint8_t>& hmac = hmac_history[i];
    Label label(i, leaf_length_, bits_per_level_);
    UpdateLeafCache(label.value(), hmac.data(), hmac.size());
  }
}

void SignInHashTree::GenerateAndStoreHashCache() {
  PopulateLeafCache();
  GenerateInnerHashArray();
}

void SignInHashTree::GenerateInnerHashArray() {
  CalculateHash(Label(0, 0, bits_per_level_));
}

bool SignInHashTree::StoreLabel(const Label& label,
                                const std::vector<uint8_t>& hmac,
                                const std::vector<uint8_t>& cred_metadata,
                                bool metadata_lost) {
  if (hmac.size() != kHashSize) {
    LOG(WARNING) << "Unexpected MAC size when storing label " << label.value();
    return false;
  }

  if (IsLeafLabel(label)) {
    // Place the data in a protobuf and then write out to storage.
    HashTreeLeafData leaf_data;
    leaf_data.set_mac(hmac.data(), hmac.size());
    leaf_data.set_metadata_lost(metadata_lost);
    leaf_data.set_credential_metadata(cred_metadata.data(),
                                      cred_metadata.size());

    std::vector<uint8_t> merged_blob(leaf_data.ByteSizeLong());
    if (!leaf_data.SerializeToArray(merged_blob.data(), merged_blob.size())) {
      LOG(ERROR) << "Couldn't serialize leaf data, label: " << label.value();
      return false;
    }
    if (plt_.StoreValue(label.value(), merged_blob) != PLT_SUCCESS) {
      LOG(ERROR) << "Couldn't store label: " << label.value() << " in PLT.";
      return false;
    }
    UpdateLeafCache(label.value(), hmac.data(), hmac.size());
  } else {
    UpdateInnerHashArray(label.cache_index(), hmac.data(), hmac.size());
  }

  UpdateHashCacheLabelPath(label);
  return true;
}

bool SignInHashTree::RemoveLabel(const Label& label) {
  // Update the PLT if |label| is a leaf node.
  if (!IsLeafLabel(label)) {
    LOG(ERROR) << "Label provided is not for leaf node: " << label.value();
    return false;
  }

  if (plt_.RemoveKey(label.value()) != PLT_SUCCESS) {
    LOG(ERROR) << "Couldn't remove label: " << label.value() << " in PLT.";
    return false;
  }

  std::vector<uint8_t> hmac(kHashSize, 0);
  UpdateLeafCache(label.value(), hmac.data(), hmac.size());
  UpdateHashCacheLabelPath(label);
  return true;
}

bool SignInHashTree::GetLabelData(const Label& label,
                                  std::vector<uint8_t>* hmac,
                                  std::vector<uint8_t>* cred_metadata,
                                  bool* metadata_lost) {
  // If it is a leaf node, just get all the data from the PLT directly.
  if (IsLeafLabel(label)) {
    std::vector<uint8_t> merged_blob;
    PLTError ret_val = plt_.GetValue(label.value(), &merged_blob);
    if (ret_val == PLT_KEY_NOT_FOUND) {
      // Return an all-zero HMAC.
      hmac->assign(kHashSize, 0);
      return true;
    }

    if (ret_val != PLT_SUCCESS) {
      LOG(WARNING) << "Couldn't get key: " << label.value() << " in PLT.";
      return false;
    }

    HashTreeLeafData leaf_data;
    if (!leaf_data.ParseFromArray(merged_blob.data(), merged_blob.size())) {
      LOG(WARNING) << "Couldn't deserialize leaf data for label "
                   << label.value();
      return false;
    }

    if (leaf_data.mac().size() != kHashSize) {
      LOG(WARNING) << "Unexpected MAC size for label " << label.value();
      return false;
    }

    hmac->assign(leaf_data.mac().begin(), leaf_data.mac().end());
    cred_metadata->assign(leaf_data.credential_metadata().begin(),
                          leaf_data.credential_metadata().end());
    *metadata_lost = leaf_data.metadata_lost();
  } else {
    // If it is a inner leaf, get the value from the HashCache file.
    hmac->assign(inner_hash_array_[label.cache_index()],
                 inner_hash_array_[label.cache_index()] + kHashSize);
  }
  return true;
}

SignInHashTree::Label SignInHashTree::GetFreeLabel() {
  // Get the list of currently used labels, then pick a random
  // label from the remaining ones.
  std::vector<uint64_t> used_keys;
  plt_.GetUsedKeys(&used_keys);
  uint64_t num_max_labels = 1 << leaf_length_;
  uint64_t num_free_keys = num_max_labels - used_keys.size();
  if (num_free_keys <= 0) {
    // No more labels.
    return Label();
  }

  uint64_t new_label;
  GetSecureRandom(reinterpret_cast<unsigned char*>(&new_label),
                  sizeof(new_label));
  new_label %= num_free_keys;
  std::sort(used_keys.begin(), used_keys.end());
  for (uint64_t used_key : used_keys) {
    if (used_key > new_label) {
      break;
    }
    new_label++;
  }
  CHECK_LT(new_label, num_max_labels);
  CHECK(!plt_.KeyExists(new_label));

  return Label(new_label, leaf_length_, bits_per_level_);
}

void SignInHashTree::GetRootHash(std::vector<uint8_t>* root_hash) {
  GenerateInnerHashArray();
  root_hash->assign(inner_hash_array_[0], inner_hash_array_[0] + kHashSize);
}

std::vector<uint8_t> SignInHashTree::CalculateHash(const Label& label) {
  std::vector<uint8_t> ret_val;
  if (IsLeafLabel(label)) {
    ret_val.assign(leaf_cache_array_[label.value()],
                   leaf_cache_array_[label.value()] + kHashSize);
    return ret_val;
  }

  // Join all the child hashes / HMACs together, and hash the result.
  std::vector<uint8_t> input_buffer;
  for (uint64_t i = 0; i < fan_out_; i++) {
    Label child_label = label.Extend(i);
    std::vector<uint8_t> child_hash = CalculateHash(child_label);
    input_buffer.insert(input_buffer.end(), child_hash.begin(),
                        child_hash.end());
  }
  ret_val = Sha256(input_buffer);

  // Update the hash cache with the new value.
  UpdateInnerHashArray(label.cache_index(), ret_val.data(), ret_val.size());
  return ret_val;
}

void SignInHashTree::UpdateHashCacheLabelPath(const Label& label) {
  Label cur_label = label;
  while (!cur_label.is_root()) {
    Label parent = cur_label.GetParent();
    std::vector<uint8_t> input_buffer;
    for (uint64_t i = 0; i < fan_out_; i++) {
      Label child_label = parent.Extend(i);
      uint8_t* array_address;
      if (IsLeafLabel(child_label)) {
        array_address = leaf_cache_array_[child_label.value()];
      } else {
        array_address = inner_hash_array_[child_label.cache_index()];
      }
      input_buffer.insert(input_buffer.end(), array_address,
                          array_address + kHashSize);
    }
    brillo::Blob result_hash = Sha256(input_buffer);
    UpdateInnerHashArray(parent.cache_index(), result_hash.data(),
                         result_hash.size());
    cur_label = parent;
  }
}

void SignInHashTree::UpdateInnerHashArray(uint32_t index,
                                          const uint8_t* data,
                                          size_t size) {
  CHECK_EQ(kHashSize, size);
  CHECK_LT(index, inner_hash_vector_.size() / kHashSize);
  memcpy(inner_hash_array_[index], data, kHashSize);
}

void SignInHashTree::UpdateLeafCache(uint32_t index,
                                     const uint8_t* data,
                                     size_t size) {
  CHECK_EQ(kHashSize, size);
  CHECK_LT(index, leaf_cache_.length() / kHashSize);
  memcpy(leaf_cache_array_[index], data, kHashSize);
}

}  // namespace cryptohome
