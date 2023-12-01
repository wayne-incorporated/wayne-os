// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_CONSTS_H_
#define SHILL_CELLULAR_CELLULAR_CONSTS_H_

namespace shill {

namespace cellular {

// APN info properties added in runtime.
// Property added in shill to the last good APN to be able to reset/obsolete
// it by changing the version.
const char kApnVersionProperty[] = "version";
const int kCurrentApnCacheVersion = 2;

// APN Source.
const char kApnSourceMoDb[] = "modb";
const char kApnSourceModem[] = "modem";
const char kApnSourceFallback[] = "fallback";

}  // namespace cellular

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_CONSTS_H_
