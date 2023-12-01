// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_CLIENT_U2F_CLIENT_EXPORT_H_
#define U2FD_CLIENT_U2F_CLIENT_EXPORT_H_

// Use this for any class or function that needs to be exported from
// libu2fd-corp. E.g. U2F_CLIENT_EXPORT void foo();
#define U2F_CLIENT_EXPORT __attribute__((__visibility__("default")))

#endif  // U2FD_CLIENT_U2F_CLIENT_EXPORT_H_
