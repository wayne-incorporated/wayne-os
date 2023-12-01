// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_UTILS_VALUE_UTILS_H_
#define RUNTIME_PROBE_UTILS_VALUE_UTILS_H_

#include <string>

#include <base/values.h>

namespace runtime_probe {
// Append the given |prefix| to each key in the |dict_value|.
void PrependToDVKey(base::Value* dict_value, const std::string& prefix);

// Change the name of key |old_key| to |new_key|.
bool RenameKey(base::Value* dv,
               const std::string& old_key,
               const std::string& new_key);

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_UTILS_VALUE_UTILS_H_
