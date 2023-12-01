// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <errno.h>
#include <linux/dma-buf.h>
#include <linux/sync_file.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <cstdio>
#include <cstring>

#include "sommelier-dma-buf.h"  // NOLINT(build/include_directory)

// Shamelessly stolen from libsync.
static int sync_wait(int sync_file_fd, int timeout) {
  struct pollfd fds;
  int ret;

  if (sync_file_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  fds.fd = sync_file_fd;
  fds.events = POLLIN;

  do {
    ret = poll(&fds, 1, timeout);
    if (ret > 0) {
      if (fds.revents & (POLLERR | POLLNVAL)) {
        errno = EINVAL;
        return -1;
      }
      return 0;
    } else if (ret == 0) {
      errno = ETIME;
      return -1;
    }
  } while (ret == -1 && (errno == EINTR || errno == EAGAIN));

  return ret;
}

static int sl_ioctl(int fd,
                    unsigned long request,  // NOLINT(runtime/int)
                    void* arg) {
  int ret;

  do {
    ret = ioctl(fd, request, arg);
  } while (ret == -1 && (errno == EAGAIN || errno == EINTR));

  return ret;
}

static bool sl_dmabuf_sync_is_driver(int sync_file_fd, const char* name) {
  struct sync_file_info sfi = {};
  int ret = 0;
  ret = sl_ioctl(sync_file_fd, SYNC_IOC_FILE_INFO, &sfi);

  if (ret == 0 && strncmp(sfi.name, name, strlen(name)) == 0)
    return true;

  return false;
}

bool sl_dmabuf_sync_is_virtgpu(int sync_file_fd) {
  return sl_dmabuf_sync_is_driver(sync_file_fd, "virtio_gpu");
}

// Attempt to idle-wait on a sync_file that typically represents pending GPU
// rendering work.
void sl_dmabuf_sync_wait(int sync_file_fd) {
  int ret;
  // "stub" means there was no real fence attached.
  if (sl_dmabuf_sync_is_driver(sync_file_fd, "stub"))
    return;

  // Wait at most for 1 second, otherwise all wayland event processing is
  // blocked.
  ret = sync_wait(sync_file_fd, 1000);
  if (ret == -1 && errno == ETIME) {
    struct sync_file_info sfi = {};

    ret = sl_ioctl(sync_file_fd, SYNC_IOC_FILE_INFO, &sfi);
    fprintf(stderr, "Fence wait timeout. Possible GPU hang! fd:%d name:%s\n",
            sync_file_fd, ret < 0 ? "<unknown>" : sfi.name);
  }
}

int sl_dmabuf_get_read_sync_file(int dmabuf_fd, int& sync_file_fd) {
  struct dma_buf_export_sync_file sync_file = {};
  int ret = 0;

  sync_file.flags = DMA_BUF_SYNC_READ;
  ret = sl_ioctl(dmabuf_fd, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, &sync_file);

  if (!ret) {
    sync_file_fd = sync_file.fd;
    return 0;
  }

  assert(ret < 0);
  return errno;
}
