// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_EXPORT_H_
#define NET_BASE_EXPORT_H_

#define NET_BASE_EXPORT __attribute__((__visibility__("default")))
#define NET_BASE_PRIVATE __attribute__((__visibility__("hidden")))

#endif  //  NET_BASE_EXPORT_H_
