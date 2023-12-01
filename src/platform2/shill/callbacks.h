// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CALLBACKS_H_
#define SHILL_CALLBACKS_H_

#include <map>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <brillo/any.h>

#include "shill/data_types.h"
#include "shill/error.h"
#include "shill/store/key_value_store.h"

namespace shill {

class Error;
// Convenient typedefs for some commonly used callbacks.
using ResultCallback = base::OnceCallback<void(const Error&)>;
using ResultVariantDictionariesCallback =
    base::OnceCallback<void(const Error&, const VariantDictionaries&)>;
using ResultVariantDictionariesOnceCallback =
    base::OnceCallback<void(const VariantDictionaries&, const Error&)>;
using EnabledStateChangedCallback = base::OnceCallback<void(const Error&)>;
using KeyValueStoreCallback =
    base::OnceCallback<void(const KeyValueStore&, const Error&)>;
using KeyValueStoresCallback =
    base::OnceCallback<void(const std::vector<KeyValueStore>&, const Error&)>;
using RpcIdentifierCallback =
    base::OnceCallback<void(const RpcIdentifier&, const Error&)>;
using StringCallback =
    base::OnceCallback<void(const std::string&, const Error&)>;
using ResultStringmapsCallback =
    base::OnceCallback<void(const Stringmaps&, const Error&)>;
using BrilloAnyCallback = base::OnceCallback<void(
    const std::map<uint32_t, brillo::Any>&, const Error&)>;

}  // namespace shill

#endif  // SHILL_CALLBACKS_H_
