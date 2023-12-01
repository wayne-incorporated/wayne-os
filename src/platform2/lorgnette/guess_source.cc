// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>

#include "lorgnette/guess_source.h"

lorgnette::SourceType GuessSourceType(const std::string& name) {
  std::string lowercase = base::ToLowerASCII(name);

  if (lowercase == "fb" || lowercase == "flatbed" || lowercase == "platen")
    return lorgnette::SOURCE_PLATEN;

  if (lowercase == "adf" || lowercase == "adf front" ||
      lowercase == "adf simplex" || lowercase == "automatic document feeder")
    return lorgnette::SOURCE_ADF_SIMPLEX;

  if (lowercase == "adf duplex")
    return lorgnette::SOURCE_ADF_DUPLEX;

  if (lowercase == base::ToLowerASCII(lorgnette::kUnspecifiedDefaultSourceName))
    return lorgnette::SOURCE_DEFAULT;

  return lorgnette::SOURCE_UNSPECIFIED;
}
