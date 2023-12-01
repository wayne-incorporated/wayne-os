// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This module provides utility classes and a macro to make it easy to iterate
// over all the possible values of a protobuf enum. In particular it allows you
// to write simple code like:
//
// for (MyEnumType value : PROTOBUF_ENUM_ALL_VALUES(MyEnumType)) {
//   ... code that does stuff with "value" ...
// }
//
// There are some practical limitations to how this works, due to the fact that
// in cryptohome we use LITE_RUNTIME protobufs which mean that descriptors and
// reflection are unavailable. This produces two specific problems:
//   - If the enum has multiple values with the same underlying constant, this
//     iterator will only iterate over that value "once"
//   - Iterating over all values os O(max-min), not O(# of values), and so is
//     very inefficient on sparsely populated enums
// In practice, these limitations are not an issue. We generally do not use
// "allow_alias" enums which means that the first case does not happen in
// practice, and most of the enums we deal with have N values on the range
// [0,N). If you do have enums where these conditions do not hold, it is not
// recommended that you use this library for iteration.

#ifndef CRYPTOHOME_UTIL_PROTO_ENUM_H_
#define CRYPTOHOME_UTIL_PROTO_ENUM_H_

#include <iterator>
#include <type_traits>

namespace cryptohome {

template <typename E, int kMin, int kMax, bool (*IsValidFunc)(int)>
class ProtobufEnumAllValuesView;

// Implement a generic iterator iterating over enum values. Internally it is
// represented by the underlying enum integer value, but incrementing it will
// skip over invalid values. Note that this means that in practice increment can
// be expensive, if the enum values are sparsely populated.
template <typename E, int kMin, int kMax, bool (*IsValidFunc)(int)>
class ProtobufEnumIterator {
 public:
  static_assert(std::is_enum_v<E>,
                "this iterator is intended for use only with protobuf enums");

  // Standard iterator type aliases.
  using value_type = E;
  using iterator_category = std::forward_iterator_tag;
  using difference_type = int;
  using pointer = E*;
  using reference = E&;

  ProtobufEnumIterator() : current_(kMin) {}

  ProtobufEnumIterator(const ProtobufEnumIterator& other) = default;
  ProtobufEnumIterator& operator=(const ProtobufEnumIterator& other) = default;

  ProtobufEnumIterator operator++(int) {
    ProtobufEnumIterator other(*this);
    ++(*this);
    return other;
  }

  ProtobufEnumIterator& operator++() {
    // Make incrementing an end value a no-op. Calling ++ on this is undefined
    // behavior so we can do what we want but this is probably better than doing
    // 2 billion+ increments.
    if (current_ == kEnd) {
      return *this;
    }
    // Keep incrementing the value until we get either a valid value, or end.
    do {
      ++current_;
    } while (current_ != kEnd && !IsValidFunc(current_));
    return *this;
  }

  E operator*() const { return static_cast<E>(current_); }

  bool operator==(const ProtobufEnumIterator& rhs) const {
    return current_ == rhs.current_;
  }
  bool operator!=(const ProtobufEnumIterator& rhs) const {
    return !(*this == rhs);
  }

 private:
  friend class ProtobufEnumAllValuesView<E, kMin, kMax, IsValidFunc>;

  explicit ProtobufEnumIterator(int current) : current_(current) {}

  // The "end" sentinel value.
  static constexpr int kEnd = kMax + 1;

  // The current underlying value, or kEnd.
  int current_;
};

// Defines a "view" over all of the values in a protobuf. The view itself
// contains no state because it always represents the set of all values.
template <typename E, int kMin, int kMax, bool (*IsValidFunc)(int)>
class ProtobufEnumAllValuesView {
 public:
  static_assert(std::is_enum_v<E>,
                "this iterator is intended for use only with protobuf enums");

  using iterator = ProtobufEnumIterator<E, kMin, kMax, IsValidFunc>;

  iterator begin() const { return iterator(); }
  iterator end() const { return iterator(iterator::kEnd); }
};

}  // namespace cryptohome

// Macro to construct a ProtobufEnumAllValuesView from an enum type name,
// filling in all of the constant template parameters automatically.
// Unfortunately this has to be done with a macro and not a class or function
// because there's no generic way to find these constants and functions from
// just the enum type, only the type name.
#define PROTOBUF_ENUM_ALL_VALUES(enum_type_name)                  \
  ProtobufEnumAllValuesView<enum_type_name, enum_type_name##_MIN, \
                            enum_type_name##_MAX, &enum_type_name##_IsValid>()

#endif  // CRYPTOHOME_UTIL_PROTO_ENUM_H_
