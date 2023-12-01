// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBPASSWORDPROVIDER_LIBPASSWORDPROVIDER_EXPORT_H_
#define LIBPASSWORDPROVIDER_LIBPASSWORDPROVIDER_EXPORT_H_

// Use this for any class or function that needs to be exported
// from libpasswordprovider.
// E.g. LIBPASSWORDPROVIDER_EXPORT void foo();
#define LIBPASSWORDPROVIDER_EXPORT __attribute__((__visibility__("default")))

#endif  // LIBPASSWORDPROVIDER_LIBPASSWORDPROVIDER_EXPORT_H_
