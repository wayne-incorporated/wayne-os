// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_MAP_H_
#define CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_MAP_H_

#include <map>
#include <memory>
#include <optional>
#include <string>

#include "cryptohome/auth_blocks/auth_block_utility.h"
#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_storage_type.h"

namespace cryptohome {

// Container for storing AuthFactor instances loaded from storage.
// Must be use on single thread and sequence only.
class AuthFactorMap final {
 private:
  // Structure containing an auth factor loaded from storage along with metadata
  // about the storage it was loaded from.
  struct StoredAuthFactor {
    std::unique_ptr<AuthFactor> auth_factor;
    AuthFactorStorageType storage_type;
  };
  // Declared here in the beginning to allow us to reference the underlying
  // storage type when defining the iterator.
  using Storage = std::map<std::string, StoredAuthFactor>;

 public:
  // Class that exports a view of the underlying StoredAuthFactor.
  class ValueView {
   public:
    explicit ValueView(const StoredAuthFactor* storage) : storage_(storage) {
      CHECK(storage);
    }

    ValueView(const ValueView&) = default;
    ValueView& operator=(const ValueView&) = default;

    const AuthFactor& auth_factor() const { return *storage_->auth_factor; }

    AuthFactorStorageType storage_type() const {
      return storage_->storage_type;
    }

   protected:
    const StoredAuthFactor* storage_;
  };
  using value_type = ValueView;

  // Implementation of an iterator that exposes the underlying stored values in
  // the map as a ValueView. Note that the iterator exposes the map as a
  // sequence of values, not a sequence of key-value pairs, because the keys are
  // the auth factor label which can be read directly from the stored value.
  class iterator {
   public:
    using value_type = ValueView;
    using iterator_category = std::forward_iterator_tag;
    using difference_type = Storage::difference_type;
    using pointer = value_type*;
    using reference = value_type&;

    iterator(const iterator& other) = default;
    iterator& operator=(const iterator& other) = default;

    iterator operator++(int) {
      iterator other(*this);
      ++(*this);
      return other;
    }

    iterator& operator++() {
      ++iter_;
      return *this;
    }

    value_type operator*() const { return value_type{&iter_->second}; }

    bool operator==(const iterator& rhs) const { return iter_ == rhs.iter_; }
    bool operator!=(const iterator& rhs) const { return !(*this == rhs); }

   private:
    friend class AuthFactorMap;
    explicit iterator(Storage::const_iterator iter) : iter_(iter) {}

    Storage::const_iterator iter_;
  };
  using const_iterator = iterator;

  AuthFactorMap() = default;

  // An auth factor map can be moved but not copied as the underlying stored
  // values cannot be copied.
  AuthFactorMap(const AuthFactorMap&) = delete;
  AuthFactorMap& operator=(const AuthFactorMap&) = delete;
  AuthFactorMap(AuthFactorMap&&) = default;
  AuthFactorMap& operator=(AuthFactorMap&&) = default;

  bool empty() const { return storage_.empty(); }
  size_t size() const { return storage_.size(); }

  iterator begin() const { return iterator(storage_.begin()); }
  iterator end() const { return iterator(storage_.end()); }

  // Add a factor to the map, along with the given storage type. The factors are
  // only stored by label and so adding a new factor with the same label will
  // overwrite the prior one.
  void Add(std::unique_ptr<AuthFactor> auth_factor,
           AuthFactorStorageType storage_type);

  // Removes the factor for a given label. Does nothing if there is no factor
  // with that label.
  void Remove(const std::string& label);

  // Reports if the map contains any factors of the given storage type.
  bool HasFactorWithStorage(AuthFactorStorageType storage_type) const;

  // Return a view of the stored factor, or nullopt if there is no factor for
  // the given label.
  std::optional<ValueView> Find(const std::string& label) const;

  // Report auth factor backing store metrics.
  void ReportAuthFactorBackingStoreMetrics() const;

 private:
  Storage storage_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_FACTOR_AUTH_FACTOR_MAP_H_
