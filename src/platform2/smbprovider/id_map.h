// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_ID_MAP_H_
#define SMBPROVIDER_ID_MAP_H_

#include <algorithm>
#include <stack>
#include <unordered_map>
#include <utility>

#include <base/check_op.h>
#include <base/logging.h>

namespace smbprovider {

// Class that maps an int32_t ID to another type. Each new ID is not currently
// in use, but IDs can be reused after that item is removed from the map.
// Primarily used for handing out pseudo file descriptors.
template <typename T>
class IdMap {
 public:
  using MapType = std::unordered_map<int32_t, T>;

  explicit IdMap(int initial_value)
      : initial_id_(initial_value), next_unused_id_(initial_value) {}
  IdMap(const IdMap&) = delete;
  IdMap& operator=(const IdMap&) = delete;

  ~IdMap() = default;

  int32_t Insert(T value) {
    const int32_t next_id = GetNextId();
    DCHECK_EQ(0, ids_.count(next_id));

    ids_.emplace(next_id, std::move(value));
    return next_id;
  }

  typename MapType::const_iterator Find(int32_t id) const {
    return ids_.find(id);
  }

  typename MapType::iterator Find(int32_t id) { return ids_.find(id); }

  const T& At(int32_t id) const { return ids_.at(id); }

  bool Contains(int32_t id) const { return ids_.count(id) > 0; }

  bool Remove(int32_t id) {
    // If the id was being used add to the free list to be reused.
    if (ids_.erase(id) > 0) {
      free_ids_.push(id);
      return true;
    }

    return false;
  }

  void Reset() {
    ids_.clear();

    // Empty out |free_ids_|.
    free_ids_ = {};

    next_unused_id_ = initial_id_;
  }

  size_t Count() const { return ids_.size(); }

  bool Empty() const { return ids_.empty(); }

  typename MapType::const_iterator Begin() const { return ids_.begin(); }
  typename MapType::iterator Begin() { return ids_.begin(); }

  typename MapType::const_iterator End() const { return ids_.end(); }
  typename MapType::iterator End() { return ids_.end(); }

 private:
  // Returns the next ID and updates the internal state to ensure that
  // an ID that is already in use is not returned.
  int32_t GetNextId() {
    if (!free_ids_.empty()) {
      int32_t next_id = free_ids_.top();
      free_ids_.pop();
      return next_id;
    }

    return next_unused_id_++;
  }

  MapType ids_;
  std::stack<int32_t> free_ids_;
  const int32_t initial_id_;
  int32_t next_unused_id_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_ID_MAP_H_
