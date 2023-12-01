// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_ACCESSOR_INTERFACE_H_
#define SHILL_STORE_ACCESSOR_INTERFACE_H_

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "shill/data_types.h"
#include "shill/store/key_value_store.h"

namespace shill {

class Error;

// A templated abstract base class for objects that can be used to access
// properties stored in objects that are meant to be made available over RPC.
// The intended usage is that an object stores a maps of strings to
// AccessorInterfaces of the appropriate type, and then uses
// map[name]->Get() and map[name]->Set(value) to get and set the properties.
template <class T>
class AccessorInterface {
 public:
  AccessorInterface() = default;
  AccessorInterface(const AccessorInterface&) = delete;
  AccessorInterface& operator=(const AccessorInterface&) = delete;

  virtual ~AccessorInterface() = default;

  // Reset the property to its default value. Sets |error| on failure.
  virtual void Clear(Error* error) = 0;
  // Provides read-only access. Sets |error| on failure.
  virtual T Get(Error* error) = 0;
  // Attempts to set the wrapped value. Sets |error| on failure.  The
  // return value indicates whether or not the wrapped value was
  // modified. If the new value is the same as the old value, Set
  // returns false, but with |error| unchanged.
  virtual bool Set(const T& value, Error* error) = 0;
};

// Using a smart pointer here allows pointers to classes derived from
// AccessorInterface<> to be stored in maps and other STL container types.
using BoolAccessor = std::unique_ptr<AccessorInterface<bool>>;
using Int16Accessor = std::unique_ptr<AccessorInterface<int16_t>>;
using Int32Accessor = std::unique_ptr<AccessorInterface<int32_t>>;
using RpcIdentifierAccessor = std::unique_ptr<AccessorInterface<RpcIdentifier>>;
using RpcIdentifiersAccessor =
    std::unique_ptr<AccessorInterface<RpcIdentifiers>>;
using StringAccessor = std::unique_ptr<AccessorInterface<std::string>>;
using StringmapAccessor = std::unique_ptr<AccessorInterface<Stringmap>>;
using StringmapsAccessor = std::unique_ptr<AccessorInterface<Stringmaps>>;
using StringsAccessor = std::unique_ptr<AccessorInterface<Strings>>;
using KeyValueStoreAccessor = std::unique_ptr<AccessorInterface<KeyValueStore>>;
using KeyValueStoresAccessor =
    std::unique_ptr<AccessorInterface<KeyValueStores>>;
using Uint8Accessor = std::unique_ptr<AccessorInterface<uint8_t>>;
using ByteArrayAccessor = std::unique_ptr<AccessorInterface<ByteArray>>;
using Uint16Accessor = std::unique_ptr<AccessorInterface<uint16_t>>;
using Uint16sAccessor = std::unique_ptr<AccessorInterface<Uint16s>>;
using Uint32Accessor = std::unique_ptr<AccessorInterface<uint32_t>>;
using Uint64Accessor = std::unique_ptr<AccessorInterface<uint64_t>>;

template <typename T>
using AccessorMap =
    std::map<std::string, std::unique_ptr<AccessorInterface<T>>, std::less<>>;

}  // namespace shill

#endif  // SHILL_STORE_ACCESSOR_INTERFACE_H_
