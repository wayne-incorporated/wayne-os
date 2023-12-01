// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_GRAPHICS_HEADER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_GRAPHICS_HEADER_H_

// It'll include X11 library finally, which is notoriously problematic. In X11
// header, they define |Status| as |int| and break many code.
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <GLES3/gl32.h>

// Undefine |Status| here to save others.
#undef Status

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_GRAPHICS_HEADER_H_
