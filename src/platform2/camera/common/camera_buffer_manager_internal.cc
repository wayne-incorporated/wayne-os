/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_buffer_manager_internal.h"

#include <xf86drm.h>

#include "cros-camera/common.h"

namespace {

const int32_t kDrmNumNodes = 64;
const int32_t kMinNodeNumber = 128;

}  // namespace

namespace cros {

namespace internal {

struct gbm_device* CreateGbmDevice() {
  int fd;
  int32_t min_node = kMinNodeNumber;
  int32_t max_node = kMinNodeNumber + kDrmNumNodes;
  struct gbm_device* gbm = nullptr;

#ifdef MINIGBM
  gbm = minigbm_create_default_device(&fd);
  if (gbm && fd >= 0) {
    VLOGF(1) << "Opened gbm device with minigbm helper";
    return gbm;
  }
#endif

  for (int i = min_node; i < max_node; i++) {
    fd = drmOpenRender(i);
    if (fd < 0) {
      continue;
    }

    drmVersionPtr version = drmGetVersion(fd);
    if (!strcmp("vgem", version->name)) {
      drmFreeVersion(version);
      close(fd);
      continue;
    }

    gbm = gbm_create_device(fd);
    if (!gbm) {
      drmFreeVersion(version);
      close(fd);
      continue;
    }

    VLOGF(1) << "Opened gbm device on render node " << version->name;
    drmFreeVersion(version);
    return gbm;
  }

  return nullptr;
}

}  // namespace internal

}  // namespace cros
