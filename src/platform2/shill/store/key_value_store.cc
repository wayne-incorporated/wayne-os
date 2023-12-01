// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/key_value_store.h"

#include <string>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/strings/string_piece.h>

#include "shill/logging.h"

namespace shill {

KeyValueStore::KeyValueStore() = default;

void KeyValueStore::Clear() {
  properties_.clear();
}

bool KeyValueStore::IsEmpty() const {
  return properties_.empty();
}

void KeyValueStore::CopyFrom(const KeyValueStore& b) {
  properties_ = b.properties_;
}

bool KeyValueStore::operator==(const KeyValueStore& rhs) const {
  return properties_ == rhs.properties_;
}

bool KeyValueStore::operator!=(const KeyValueStore& rhs) const {
  return properties_ != rhs.properties_;
}

bool KeyValueStore::ContainsVariant(base::StringPiece name) const {
  return base::Contains(properties_, name);
}

const brillo::Any& KeyValueStore::GetVariant(base::StringPiece name) const {
  const auto it(properties_.find(name));
  CHECK(it != properties_.end());
  return it->second;
}

void KeyValueStore::SetVariant(base::StringPiece name,
                               const brillo::Any& value) {
  properties_.insert_or_assign(std::string(name), value);
}

void KeyValueStore::Remove(base::StringPiece name) {
  // Note that map::erase does not support transparent comparator.
  const auto it = properties_.find(name);
  if (it != properties_.end()) {
    properties_.erase(it);
  }
}

// static.
brillo::VariantDictionary KeyValueStore::ConvertToVariantDictionary(
    const KeyValueStore& in_store) {
  brillo::VariantDictionary out_dict;
  for (const auto& key_value_pair : in_store.properties_) {
    if (key_value_pair.second.IsTypeCompatible<KeyValueStore>()) {
      // Special handling for nested KeyValueStore (convert it to
      // nested brillo::VariantDictionary).
      brillo::VariantDictionary dict = ConvertToVariantDictionary(
          key_value_pair.second.Get<KeyValueStore>());
      out_dict.emplace(key_value_pair.first, dict);
    } else {
      out_dict.insert(key_value_pair);
    }
  }
  return out_dict;
}

// static.
KeyValueStore KeyValueStore::ConvertFromVariantDictionary(
    const brillo::VariantDictionary& in_dict) {
  KeyValueStore out_store;
  for (const auto& key_value_pair : in_dict) {
    if (key_value_pair.second.IsTypeCompatible<brillo::VariantDictionary>()) {
      // Special handling for nested brillo::VariantDictionary (convert it to
      // nested KeyValueStore).
      KeyValueStore store = ConvertFromVariantDictionary(
          key_value_pair.second.Get<brillo::VariantDictionary>());
      out_store.properties_.emplace(key_value_pair.first, store);
    } else {
      out_store.properties_.insert(key_value_pair);
    }
  }
  return out_store;
}

}  // namespace shill
