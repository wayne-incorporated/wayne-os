// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_UNIQUE_QUEUE_H_
#define DLCSERVICE_UNIQUE_QUEUE_H_

#include <list>
#include <unordered_map>
#include <utility>

namespace dlcservice {

// |UniqueQueue| is a queue that only holds unique elements.
// - Constant time deletion of an element.
// - Constant time check of an element.
// Template arguments:
// - |T| the element type to queue.
// - |T_Hasher| the hashing function for |T|.
template <typename T, typename T_Hasher>
class UniqueQueue {
 public:
  UniqueQueue() = default;
  virtual ~UniqueQueue() = default;

  // Returns true if there are any elements.
  bool Empty() const { return list_.empty(); }

  // Returns true if element |t| exists.
  bool Has(const T& t) { return map_.find(t) != map_.end(); }

  // Inserts the element to the back of the queue.
  void Push(const T& t) {
    if (!Has(t)) {
      list_.push_back(t);
      map_.insert({{t, --list_.end()}});
    }
  }

  // Returns a const reference to the first element.
  const T& Peek() const { return list_.front(); }

  // Removes the front element.
  void Pop() {
    map_.erase(list_.front());
    list_.pop_front();
  }

  // Removes a single element |t|.
  void Erase(const T& t) {
    auto iter = map_.find(t);
    if (iter == map_.end())
      return;
    list_.erase(iter->second);
    map_.erase(iter);
  }

  // Remove all elements.
  void Clear() {
    list_.clear();
    map_.clear();
  }

 private:
  std::list<T> list_;
  std::unordered_map<T, typename decltype(list_)::iterator, T_Hasher> map_;

  UniqueQueue(const UniqueQueue&) = delete;
  UniqueQueue& operator=(const UniqueQueue&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_UNIQUE_QUEUE_H_
