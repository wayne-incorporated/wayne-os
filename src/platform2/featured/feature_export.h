// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef FEATURED_FEATURE_EXPORT_H_
#define FEATURED_FEATURE_EXPORT_H_

#define FEATURE_EXPORT __attribute__((__visibility__("default")))
#define FEATURE_PRIVATE __attribute__((__visibility__("hidden")))

#endif  // FEATURED_FEATURE_EXPORT_H_
