// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "../sommelier.h"          // NOLINT(build/include_directory)
#include "../sommelier-tracing.h"  // NOLINT(build/include_directory)
#include "sommelier-dma-buf.h"     // NOLINT(build/include_directory)

#include <assert.h>
#include <gbm.h>
#include <libdrm/drm_fourcc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xf86drm.h>

#include "../virtualization/linux-headers/virtgpu_drm.h"  // NOLINT(build/include_directory)

#include "drm-server-protocol.h"  // NOLINT(build/include_directory)
#include "linux-dmabuf-unstable-v1-client-protocol.h"  // NOLINT(build/include_directory)

struct sl_host_drm {
  struct sl_context* ctx;
  uint32_t version;
  struct wl_resource* resource;
  struct zwp_linux_dmabuf_v1* linux_dmabuf_proxy;
  struct wl_callback* callback;
};

static void sl_drm_authenticate(struct wl_client* client,
                                struct wl_resource* resource,
                                uint32_t id) {
  TRACE_EVENT("drm", "sl_drm_authenticate");
  wl_drm_send_authenticated(resource);
}

static void sl_drm_create_buffer(struct wl_client* client,
                                 struct wl_resource* resource,
                                 uint32_t id,
                                 uint32_t name,
                                 int32_t width,
                                 int32_t height,
                                 uint32_t stride,
                                 uint32_t format) {
  assert(0);
}

static void sl_drm_create_planar_buffer(struct wl_client* client,
                                        struct wl_resource* resource,
                                        uint32_t id,
                                        uint32_t name,
                                        int32_t width,
                                        int32_t height,
                                        uint32_t format,
                                        int32_t offset0,
                                        int32_t stride0,
                                        int32_t offset1,
                                        int32_t stride1,
                                        int32_t offset2,
                                        int32_t stride2) {
  assert(0);
}

static void sl_drm_sync(struct sl_context* ctx,
                        struct sl_sync_point* sync_point) {
  int drm_fd = gbm_device_get_fd(ctx->gbm);
  struct drm_prime_handle prime_handle;
  int sync_file_fd;
  int ret;

  // Attempt to export a sync_file from prime buffer and wait explicitly.
  ret = sl_dmabuf_get_read_sync_file(sync_point->fd, sync_file_fd);
  if (!ret) {
    TRACE_EVENT("drm", "sl_drm_sync: sync_wait", "prime_fd", sync_point->fd);
    sl_dmabuf_sync_wait(sync_file_fd);
    close(sync_file_fd);
    return;
  }

  // Fallback to waiting on a virtgpu buffer's implicit fence.
  //
  // First imports the prime fd to a gem handle. This will fail if this
  // function was not passed a prime handle that can be imported by the drm
  // device given to sommelier.
  memset(&prime_handle, 0, sizeof(prime_handle));
  prime_handle.fd = sync_point->fd;
  TRACE_EVENT("drm", "sl_drm_sync: virtgpu_wait", "prime_fd", prime_handle.fd);
  ret = drmIoctl(drm_fd, DRM_IOCTL_PRIME_FD_TO_HANDLE, &prime_handle);
  if (!ret) {
    struct drm_virtgpu_3d_wait wait_arg;
    struct drm_gem_close gem_close;

    // Then attempts to wait for GPU operations to complete. This will fail
    // silently if the drm device passed to sommelier is not a virtio-gpu
    // device.
    memset(&wait_arg, 0, sizeof(wait_arg));
    wait_arg.handle = prime_handle.handle;
    drmIoctl(drm_fd, DRM_IOCTL_VIRTGPU_WAIT, &wait_arg);

    // Always close the handle we imported.
    memset(&gem_close, 0, sizeof(gem_close));
    gem_close.handle = prime_handle.handle;
    drmIoctl(drm_fd, DRM_IOCTL_GEM_CLOSE, &gem_close);
  }
}

static void sl_drm_create_prime_buffer(struct wl_client* client,
                                       struct wl_resource* resource,
                                       uint32_t id,
                                       int32_t name,
                                       int32_t width,
                                       int32_t height,
                                       uint32_t format,
                                       int32_t offset0,
                                       int32_t stride0,
                                       int32_t offset1,
                                       int32_t stride1,
                                       int32_t offset2,
                                       int32_t stride2) {
  TRACE_EVENT("drm", "sl_drm_create_prime_buffer", "id", id);
  struct sl_host_drm* host =
      static_cast<sl_host_drm*>(wl_resource_get_user_data(resource));
  struct zwp_linux_buffer_params_v1* buffer_params;

  assert(name >= 0);
  assert(!offset1);
  assert(!stride1);
  assert(!offset2);
  assert(!stride2);

  // Attempts to correct stride0 with virtio-gpu specific resource information,
  // if available.  Ideally mesa/gbm should have the correct stride. Remove
  // after crbug.com/892242 is resolved in mesa.
  int is_gpu_buffer = 0;
  uint64_t format_modifier = DRM_FORMAT_MOD_INVALID;
  if (host->ctx->gbm) {
    int drm_fd = gbm_device_get_fd(host->ctx->gbm);
    struct drm_prime_handle prime_handle;
    int ret;

    // First imports the prime fd to a gem handle. This will fail if this
    // function was not passed a prime handle that can be imported by the drm
    // device given to sommelier.
    memset(&prime_handle, 0, sizeof(prime_handle));
    prime_handle.fd = name;
    ret = drmIoctl(drm_fd, DRM_IOCTL_PRIME_FD_TO_HANDLE, &prime_handle);
    if (!ret) {
      struct drm_virtgpu_resource_info_cros info_arg;
      struct drm_gem_close gem_close;

      // Then attempts to get resource information. This will fail silently if
      // the drm device passed to sommelier is not a virtio-gpu device.
      memset(&info_arg, 0, sizeof(info_arg));
      info_arg.bo_handle = prime_handle.handle;
      info_arg.type = VIRTGPU_RESOURCE_INFO_TYPE_EXTENDED;
      ret = drmIoctl(drm_fd, DRM_IOCTL_VIRTGPU_RESOURCE_INFO_CROS, &info_arg);
      // Correct stride0 if we are able to get proper resource info.
      if (!ret) {
        if (info_arg.stride) {
          stride0 = info_arg.stride;
          format_modifier = info_arg.format_modifier;
        }
        is_gpu_buffer = 1;
      }

      // Always close the handle we imported.
      memset(&gem_close, 0, sizeof(gem_close));
      gem_close.handle = prime_handle.handle;
      drmIoctl(drm_fd, DRM_IOCTL_GEM_CLOSE, &gem_close);
    }
  }

  buffer_params =
      zwp_linux_dmabuf_v1_create_params(host->ctx->linux_dmabuf->internal);
  zwp_linux_buffer_params_v1_add(buffer_params, name, 0, offset0, stride0,
                                 format_modifier >> 32,
                                 format_modifier & 0xffffffff);

  struct sl_host_buffer* host_buffer =
      sl_create_host_buffer(host->ctx, client, id,
                            zwp_linux_buffer_params_v1_create_immed(
                                buffer_params, width, height, format, 0),
                            width, height, /*is_drm=*/true);
  if (is_gpu_buffer) {
    host_buffer->sync_point = sl_sync_point_create(name);
    host_buffer->sync_point->sync = sl_drm_sync;
    host_buffer->shm_format = sl_shm_format_for_drm_format(format);

    // Create our DRM PRIME mmap container
    // This is simply a container that records necessary information
    // to map the DRM buffer through the GBM API's.
    // The GBM API's may need to perform a rather heavy copy of the
    // buffer into memory accessible by the CPU to perform the mapping
    // operation.
    // For this reason, the GBM mapping API's will not be used until we
    // are absolutely certain that the buffers contents need to be
    // accessed. This will be done through a call to sl_mmap_begin_access.
    //
    // We are also checking for a single plane format as this container
    // is currently only defined for single plane format buffers.

    if (sl_shm_num_planes_for_shm_format(host_buffer->shm_format) == 1) {
      host_buffer->shm_mmap = sl_drm_prime_mmap_create(
          host->ctx->gbm, name,
          sl_shm_bpp_for_shm_format(host_buffer->shm_format),
          sl_shm_num_planes_for_shm_format(host_buffer->shm_format), stride0,
          width, height, format);

      // The buffer_resource must be set appropriately here or else
      // we will not perform the appropriate release at the end of
      // sl_host_surface_commit (see the end of that function for details).
      //
      // This release should only be done IF we successfully perform
      // the xshape interjection, as the host compositor will be using
      // a different buffer. For non shaped windows or fallbacks due
      // to map failure, where the buffer is relayed onto the host,
      // we should not release the buffer. That is the responsibility
      // of the host. The fallback path/non shape path takes care of this
      // by setting the host_surface contents_shm_mmap to nullptr.
      host_buffer->shm_mmap->buffer_resource = host_buffer->resource;
    }
  } else {
    close(name);
  }

  zwp_linux_buffer_params_v1_destroy(buffer_params);
}

static const struct wl_drm_interface sl_drm_implementation = {
    sl_drm_authenticate, sl_drm_create_buffer, sl_drm_create_planar_buffer,
    sl_drm_create_prime_buffer};

static void sl_destroy_host_drm(struct wl_resource* resource) {
  struct sl_host_drm* host =
      static_cast<sl_host_drm*>(wl_resource_get_user_data(resource));

  zwp_linux_dmabuf_v1_destroy(host->linux_dmabuf_proxy);
  wl_callback_destroy(host->callback);
  wl_resource_set_user_data(resource, nullptr);
  delete host;
}

static void sl_drm_format(void* data,
                          struct zwp_linux_dmabuf_v1* linux_dmabuf,
                          uint32_t format) {
  struct sl_host_drm* host = static_cast<sl_host_drm*>(
      zwp_linux_dmabuf_v1_get_user_data(linux_dmabuf));

  switch (format) {
    case WL_DRM_FORMAT_RGB565:
    case WL_DRM_FORMAT_ARGB8888:
    case WL_DRM_FORMAT_ABGR8888:
    case WL_DRM_FORMAT_XRGB8888:
    case WL_DRM_FORMAT_XBGR8888:
      wl_drm_send_format(host->resource, format);
      break;
    default:
      break;
  }
}

static void sl_drm_modifier(void* data,
                            struct zwp_linux_dmabuf_v1* linux_dmabuf,
                            uint32_t format,
                            uint32_t modifier_hi,
                            uint32_t modifier_lo) {}

static const struct zwp_linux_dmabuf_v1_listener sl_linux_dmabuf_listener = {
    sl_drm_format, sl_drm_modifier};

static void sl_drm_callback_done(void* data,
                                 struct wl_callback* callback,
                                 uint32_t serial) {
  struct sl_host_drm* host =
      static_cast<sl_host_drm*>(wl_callback_get_user_data(callback));

  if (host->ctx->drm_device)
    wl_drm_send_device(host->resource, host->ctx->drm_device);
  if (host->version >= WL_DRM_CREATE_PRIME_BUFFER_SINCE_VERSION)
    wl_drm_send_capabilities(host->resource, WL_DRM_CAPABILITY_PRIME);
}

static const struct wl_callback_listener sl_drm_callback_listener = {
    sl_drm_callback_done};

static void sl_bind_host_drm(struct wl_client* client,
                             void* data,
                             uint32_t version,
                             uint32_t id) {
  struct sl_context* ctx = (struct sl_context*)data;
  struct sl_host_drm* host = new sl_host_drm();
  host->ctx = ctx;
  host->version = MIN(version, 2);
  host->resource =
      wl_resource_create(client, &wl_drm_interface, host->version, id);
  wl_resource_set_implementation(host->resource, &sl_drm_implementation, host,
                                 sl_destroy_host_drm);

  host->linux_dmabuf_proxy = static_cast<zwp_linux_dmabuf_v1*>(wl_registry_bind(
      wl_display_get_registry(ctx->display), ctx->linux_dmabuf->id,
      &zwp_linux_dmabuf_v1_interface, ctx->linux_dmabuf->version));
  zwp_linux_dmabuf_v1_add_listener(host->linux_dmabuf_proxy,
                                   &sl_linux_dmabuf_listener, host);

  host->callback = wl_display_sync(ctx->display);
  wl_callback_add_listener(host->callback, &sl_drm_callback_listener, host);
}

struct sl_global* sl_drm_global_create(struct sl_context* ctx) {
  assert(ctx->linux_dmabuf);

  // Early out if DMABuf protocol version is not sufficient.
  if (ctx->linux_dmabuf->version < 2)
    return nullptr;

  return sl_global_create(ctx, &wl_drm_interface, 2, ctx, sl_bind_host_drm);
}
