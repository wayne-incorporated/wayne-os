// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This header provides Undefined Behavior Sanitizer specific macros.
//
#ifndef LIBBRILLO_BRILLO_UBSAN_H_
#define LIBBRILLO_BRILLO_UBSAN_H_

// Cannot use __has_feature(undefined_behavior_sanitizer) because we do not
// pass --sanitize=undefined for UBSAN builds. (It turns on too many flags
// and does not often work.) See cros-sanitizers.eclass.
#if defined(CHROMEOS_UBSAN_BUILD)
// UBSan is enabled.
#define BRILLO_UBSAN_BUILD 1
#endif

#endif  // LIBBRILLO_BRILLO_UBSAN_H_
