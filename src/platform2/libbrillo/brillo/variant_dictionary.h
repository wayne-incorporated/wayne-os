// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_VARIANT_DICTIONARY_H_
#define LIBBRILLO_BRILLO_VARIANT_DICTIONARY_H_

#include <functional>
#include <map>
#include <string>

#include <base/strings/string_piece.h>
#include <brillo/any.h>
#include <brillo/brillo_export.h>

namespace brillo {

using VariantDictionary = std::map<std::string, brillo::Any, std::less<>>;

// GetVariantValueOrDefault tries to retrieve the named key from the dictionary
// and convert it to the type T.  If the value does not exist, or the type
// conversion fails, the default value of type T is returned.
template <typename T>
T GetVariantValueOrDefault(const VariantDictionary& dictionary,
                           base::StringPiece key) {
  VariantDictionary::const_iterator it = dictionary.find(key);
  if (it == dictionary.end()) {
    return T();
  }
  return it->second.TryGet<T>();
}

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_VARIANT_DICTIONARY_H_
