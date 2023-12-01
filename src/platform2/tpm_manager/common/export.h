// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_COMMON_EXPORT_H_
#define TPM_MANAGER_COMMON_EXPORT_H_

// Use this for any class or function that needs to be exported from
// libtpm_manager. E.g. TPM_MANAGER_EXPORT void foo();
#define TPM_MANAGER_EXPORT __attribute__((__visibility__("default")))

#endif  // TPM_MANAGER_COMMON_EXPORT_H_
