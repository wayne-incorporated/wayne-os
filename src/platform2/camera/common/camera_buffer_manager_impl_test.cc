/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_buffer_manager_impl.h"

#include <sys/mman.h>

#include <functional>
#include <memory>
#include <tuple>
#include <vector>

#include <base/at_exit.h>
#include <drm_fourcc.h>
#include <gbm.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "common/camera_buffer_handle.h"
#include "common/camera_buffer_manager_internal.h"

// Dummy objects / values used for testing.
struct gbm_device {
  void* dummy;
} dummy_device;

struct gbm_bo {
  void* dummy;
} dummy_bo;

int dummy_fd = 0xdeadbeef;

void* dummy_addr = reinterpret_cast<void*>(0xbeefdead);

// Stubs for global scope mock functions.
static std::function<int(int fd)> _close;
static std::function<struct gbm_device*()> _create_gbm_device;
static std::function<int(struct gbm_device*)> _gbm_device_get_fd;
static std::function<int(struct gbm_device*, uint32_t, uint32_t)>
    _gbm_device_is_format_supported;
static std::function<void(struct gbm_device*)> _gbm_device_destroy;
static std::function<struct gbm_bo*(struct gbm_device* device,
                                    uint32_t width,
                                    uint32_t height,
                                    uint32_t format,
                                    uint32_t flags)>
    _gbm_bo_create;
static std::function<struct gbm_bo*(
    struct gbm_device* device, uint32_t type, void* buffer, uint32_t usage)>
    _gbm_bo_import;
static std::function<void*(struct gbm_bo* bo,
                           uint32_t x,
                           uint32_t y,
                           uint32_t width,
                           uint32_t height,
                           uint32_t flags,
                           uint32_t* stride,
                           void** map_data,
                           int plane)>
    _gbm_bo_map2;
static std::function<void(struct gbm_bo* bo, void* map_data)> _gbm_bo_unmap;
static std::function<size_t(struct gbm_bo* bo)> _gbm_bo_get_plane_count;
static std::function<int(struct gbm_bo* bo, size_t plane)> _gbm_bo_get_plane_fd;
static std::function<uint32_t(struct gbm_bo* bo, size_t plane)>
    _gbm_bo_get_offset;
static std::function<uint32_t(struct gbm_bo* bo, size_t plane)>
    _gbm_bo_get_stride_for_plane;
static std::function<uint64_t(struct gbm_bo* bo)> _gbm_bo_get_modifier;
static std::function<void(struct gbm_bo* bo)> _gbm_bo_destroy;
static std::function<void*(
    void* addr, size_t length, int prot, int flags, int fd, off_t offset)>
    _mmap;
static std::function<int(void* addr, size_t length)> _munmap;
static std::function<off_t(int fd, off_t offset, int whence)> _lseek;

// Implementations of the mock functions.
struct MockGbm {
  MockGbm() {
    EXPECT_EQ(_close, nullptr);
    _close = [this](int fd) { return Close(fd); };

    EXPECT_EQ(_create_gbm_device, nullptr);
    _create_gbm_device = [this]() { return CreateGbmDevice(); };

    EXPECT_EQ(_gbm_device_get_fd, nullptr);
    _gbm_device_get_fd = [this](struct gbm_device* device) {
      return GbmDeviceGetFd(device);
    };

    EXPECT_EQ(_gbm_device_is_format_supported, nullptr);
    _gbm_device_is_format_supported = [this](struct gbm_device* device,
                                             uint32_t format, uint32_t usage) {
      return GbmDeviceIsFormatSupported(device, format, usage);
    };

    EXPECT_EQ(_gbm_device_destroy, nullptr);
    _gbm_device_destroy = [this](struct gbm_device* device) {
      GbmDeviceDestroy(device);
    };

    EXPECT_EQ(_gbm_bo_create, nullptr);
    _gbm_bo_create = [this](struct gbm_device* device, uint32_t width,
                            uint32_t height, uint32_t format, uint32_t flags) {
      return GbmBoCreate(device, width, height, format, flags);
    };

    EXPECT_EQ(_gbm_bo_import, nullptr);
    _gbm_bo_import = [this](struct gbm_device* device, uint32_t type,
                            void* buffer, uint32_t usage) {
      return GbmBoImport(device, type, buffer, usage);
    };

    EXPECT_EQ(_gbm_bo_map2, nullptr);
    _gbm_bo_map2 = [this](struct gbm_bo* bo, uint32_t x, uint32_t y,
                          uint32_t width, uint32_t height, uint32_t flags,
                          uint32_t* stride, void** map_data, int plane) {
      // Point |map_data| to a dummy address.
      *map_data = reinterpret_cast<void*>(0xdeadbeef);
      return GbmBoMap2(bo, x, y, width, height, flags, stride, map_data, plane);
    };

    EXPECT_EQ(_gbm_bo_unmap, nullptr);
    _gbm_bo_unmap = [this](struct gbm_bo* bo, void* map_data) {
      GbmBoUnmap(bo, map_data);
    };

    EXPECT_EQ(_gbm_bo_get_plane_count, nullptr);
    _gbm_bo_get_plane_count = [this](struct gbm_bo* bo) {
      return GbmBoGetNumPlanes(bo);
    };

    EXPECT_EQ(_gbm_bo_get_plane_fd, nullptr);
    _gbm_bo_get_plane_fd = [this](struct gbm_bo* bo, size_t plane) {
      return GbmBoGetPlaneFd(bo, plane);
    };

    EXPECT_EQ(_gbm_bo_get_offset, nullptr);
    _gbm_bo_get_offset = [this](struct gbm_bo* bo, size_t plane) {
      return GbmBoGetPlaneOffset(bo, plane);
    };

    EXPECT_EQ(_gbm_bo_get_stride_for_plane, nullptr);
    _gbm_bo_get_stride_for_plane = [this](struct gbm_bo* bo, size_t plane) {
      return GbmBoGetPlaneStride(bo, plane);
    };

    EXPECT_EQ(_gbm_bo_get_modifier, nullptr);
    _gbm_bo_get_modifier = [this](struct gbm_bo* bo) {
      return GbmBoGetModifier(bo);
    };

    EXPECT_EQ(_gbm_bo_destroy, nullptr);
    _gbm_bo_destroy = [this](struct gbm_bo* bo) { GbmBoDestroy(bo); };

    EXPECT_EQ(_mmap, nullptr);
    _mmap = [this](void* addr, size_t length, int prot, int flags, int fd,
                   off_t offset) {
      return Mmap(addr, length, prot, flags, fd, offset);
    };

    EXPECT_EQ(_munmap, nullptr);
    _munmap = [this](void* addr, size_t length) {
      return Munmap(addr, length);
    };

    EXPECT_EQ(_lseek, nullptr);
    _lseek = [this](int fd, off_t offset, int whence) {
      return Lseek(fd, offset, whence);
    };
  }

  ~MockGbm() {
    _close = nullptr;
    _create_gbm_device = nullptr;
    _gbm_device_get_fd = nullptr;
    _gbm_device_is_format_supported = nullptr;
    _gbm_device_destroy = nullptr;
    _gbm_bo_create = nullptr;
    _gbm_bo_import = nullptr;
    _gbm_bo_map2 = nullptr;
    _gbm_bo_unmap = nullptr;
    _gbm_bo_get_plane_count = nullptr;
    _gbm_bo_get_plane_fd = nullptr;
    _gbm_bo_get_offset = nullptr;
    _gbm_bo_get_stride_for_plane = nullptr;
    _gbm_bo_get_modifier = nullptr;
    _gbm_bo_destroy = nullptr;
    _mmap = nullptr;
    _munmap = nullptr;
    _lseek = nullptr;
  }

  MOCK_METHOD(int, Close, (int));
  MOCK_METHOD(struct gbm_device*, CreateGbmDevice, ());
  MOCK_METHOD(int, GbmDeviceGetFd, (struct gbm_device*));
  MOCK_METHOD(int,
              GbmDeviceIsFormatSupported,
              (struct gbm_device*, uint32_t, uint32_t));
  MOCK_METHOD(void, GbmDeviceDestroy, (struct gbm_device*));
  MOCK_METHOD(struct gbm_bo*,
              GbmBoCreate,
              (struct gbm_device*, uint32_t, uint32_t, uint32_t, uint32_t));
  MOCK_METHOD(struct gbm_bo*,
              GbmBoImport,
              (struct gbm_device*, uint32_t, void*, uint32_t));
  MOCK_METHOD(void*,
              GbmBoMap2,
              (struct gbm_bo*,
               uint32_t,
               uint32_t,
               uint32_t,
               uint32_t,
               uint32_t,
               uint32_t*,
               void**,
               int));
  MOCK_METHOD(void, GbmBoUnmap, (struct gbm_bo*, void*));
  MOCK_METHOD(int, GbmBoGetNumPlanes, (struct gbm_bo*));
  MOCK_METHOD(int, GbmBoGetPlaneFd, (struct gbm_bo*, size_t));
  MOCK_METHOD(uint32_t, GbmBoGetPlaneOffset, (struct gbm_bo*, size_t));
  MOCK_METHOD(uint32_t, GbmBoGetPlaneStride, (struct gbm_bo*, size_t));
  MOCK_METHOD(uint64_t, GbmBoGetModifier, (struct gbm_bo*));
  MOCK_METHOD(void, GbmBoDestroy, (struct gbm_bo*));
  MOCK_METHOD(void*, Mmap, (void*, size_t, int, int, int, off_t));
  MOCK_METHOD(int, Munmap, (void*, size_t));
  MOCK_METHOD(off_t, Lseek, (int, off_t, int));
};

// global scope mock functions. These functions indirectly invoke the mock
// function implementations through the stubs.
int close(int fd) {
  return _close(fd);
}

struct gbm_device* ::cros::internal::CreateGbmDevice() {
  return _create_gbm_device();
}

int gbm_device_get_fd(struct gbm_device* device) {
  return _gbm_device_get_fd(device);
}

int gbm_device_is_format_supported(struct gbm_device* gbm,
                                   uint32_t format,
                                   uint32_t usage) {
  return _gbm_device_is_format_supported(gbm, format, usage);
}

void gbm_device_destroy(struct gbm_device* device) {
  return _gbm_device_destroy(device);
}

struct gbm_bo* gbm_bo_create(struct gbm_device* device,
                             uint32_t width,
                             uint32_t height,
                             uint32_t format,
                             uint32_t flags) {
  return _gbm_bo_create(device, width, height, format, flags);
}

struct gbm_bo* gbm_bo_import(struct gbm_device* device,
                             uint32_t type,
                             void* buffer,
                             uint32_t usage) {
  return _gbm_bo_import(device, type, buffer, usage);
}

void* gbm_bo_map2(struct gbm_bo* bo,
                  uint32_t x,
                  uint32_t y,
                  uint32_t width,
                  uint32_t height,
                  uint32_t flags,
                  uint32_t* stride,
                  void** map_data,
                  int plane) {
  return _gbm_bo_map2(bo, x, y, width, height, flags, stride, map_data, plane);
}

void gbm_bo_unmap(struct gbm_bo* bo, void* map_data) {
  return _gbm_bo_unmap(bo, map_data);
}

void gbm_bo_destroy(struct gbm_bo* bo) {
  return _gbm_bo_destroy(bo);
}

void* mmap(
    void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  return _mmap(addr, length, prot, flags, fd, offset);
}

int munmap(void* addr, size_t length) {
  return _munmap(addr, length);
}

int gbm_bo_get_plane_count(struct gbm_bo* bo) {
  return _gbm_bo_get_plane_count(bo);
}

int gbm_bo_get_plane_fd(struct gbm_bo* bo, size_t plane) {
  return _gbm_bo_get_plane_fd(bo, plane);
}

uint32_t gbm_bo_get_offset(struct gbm_bo* bo, size_t plane) {
  return _gbm_bo_get_offset(bo, plane);
}

uint32_t gbm_bo_get_stride_for_plane(struct gbm_bo* bo, size_t plane) {
  return _gbm_bo_get_stride_for_plane(bo, plane);
}

uint64_t gbm_bo_get_modifier(struct gbm_bo* bo) {
  return _gbm_bo_get_modifier(bo);
}

off_t lseek(int fd, off_t offset, int whence) {
  return _lseek(fd, offset, whence);
}

namespace cros {

namespace tests {

using ::testing::A;
using ::testing::Return;

static size_t GetFormatBpp(uint32_t drm_format) {
  switch (drm_format) {
    case DRM_FORMAT_BGR233:
    case DRM_FORMAT_C8:
    case DRM_FORMAT_R8:
    case DRM_FORMAT_RGB332:
    case DRM_FORMAT_YUV420:
    case DRM_FORMAT_YVU420:
    case DRM_FORMAT_NV12:
    case DRM_FORMAT_NV21:
      return 1;

    case DRM_FORMAT_ABGR1555:
    case DRM_FORMAT_ABGR4444:
    case DRM_FORMAT_ARGB1555:
    case DRM_FORMAT_ARGB4444:
    case DRM_FORMAT_BGR565:
    case DRM_FORMAT_BGRA4444:
    case DRM_FORMAT_BGRA5551:
    case DRM_FORMAT_BGRX4444:
    case DRM_FORMAT_BGRX5551:
    case DRM_FORMAT_GR88:
    case DRM_FORMAT_P010:
    case DRM_FORMAT_RG88:
    case DRM_FORMAT_RGB565:
    case DRM_FORMAT_RGBA4444:
    case DRM_FORMAT_RGBA5551:
    case DRM_FORMAT_RGBX4444:
    case DRM_FORMAT_RGBX5551:
    case DRM_FORMAT_UYVY:
    case DRM_FORMAT_VYUY:
    case DRM_FORMAT_XBGR1555:
    case DRM_FORMAT_XBGR4444:
    case DRM_FORMAT_XRGB1555:
    case DRM_FORMAT_XRGB4444:
    case DRM_FORMAT_YUYV:
    case DRM_FORMAT_YVYU:
      return 2;

    case DRM_FORMAT_BGR888:
    case DRM_FORMAT_RGB888:
      return 3;

    case DRM_FORMAT_ABGR2101010:
    case DRM_FORMAT_ABGR8888:
    case DRM_FORMAT_ARGB2101010:
    case DRM_FORMAT_ARGB8888:
    case DRM_FORMAT_AYUV:
    case DRM_FORMAT_BGRA1010102:
    case DRM_FORMAT_BGRA8888:
    case DRM_FORMAT_BGRX1010102:
    case DRM_FORMAT_BGRX8888:
    case DRM_FORMAT_RGBA1010102:
    case DRM_FORMAT_RGBA8888:
    case DRM_FORMAT_RGBX1010102:
    case DRM_FORMAT_RGBX8888:
    case DRM_FORMAT_XBGR2101010:
    case DRM_FORMAT_XBGR8888:
    case DRM_FORMAT_XRGB2101010:
    case DRM_FORMAT_XRGB8888:
      return 4;
  }

  LOG(ERROR) << "Unknown format: " << FormatToString(drm_format);
  return 0;
}

class CameraBufferManagerImplTest : public ::testing::Test {
 public:
  CameraBufferManagerImplTest() = default;
  CameraBufferManagerImplTest(const CameraBufferManagerImplTest&) = delete;
  CameraBufferManagerImplTest& operator=(const CameraBufferManagerImplTest&) =
      delete;

  void SetUp() override {
    EXPECT_CALL(gbm_, CreateGbmDevice())
        .Times(1)
        .WillOnce(Return(&dummy_device));
    cbm_ = new CameraBufferManagerImpl();
  }

  void TearDown() override {
    // Verify that gbm_device is properly tear down.
    EXPECT_CALL(gbm_, GbmDeviceGetFd(&dummy_device))
        .Times(1)
        .WillOnce(Return(dummy_fd));
    EXPECT_CALL(gbm_, Close(dummy_fd)).Times(1);
    EXPECT_CALL(gbm_, GbmDeviceDestroy(&dummy_device)).Times(1);
    delete cbm_;
    EXPECT_EQ(::testing::Mock::VerifyAndClear(&gbm_), true);
  }

  std::unique_ptr<camera_buffer_handle_t> CreateBuffer(
      uint32_t buffer_id,
      uint32_t drm_format,
      uint32_t hal_pixel_format,
      uint32_t width,
      uint32_t height) {
    std::unique_ptr<camera_buffer_handle_t> buffer(new camera_buffer_handle_t);
    buffer->fds[0] = dummy_fd;
    buffer->magic = kCameraBufferMagic;
    buffer->buffer_id = buffer_id;
    buffer->drm_format = drm_format;
    buffer->hal_pixel_format = hal_pixel_format;
    buffer->width = width;
    buffer->height = height;
    buffer->strides[0] = width * GetFormatBpp(drm_format);
    buffer->offsets[0] = 0;
    switch (drm_format) {
      case DRM_FORMAT_NV12:
      case DRM_FORMAT_NV21:
      case DRM_FORMAT_P010:
        buffer->strides[1] = width * GetFormatBpp(drm_format);
        buffer->offsets[1] = buffer->strides[0] * height;
        break;
      case DRM_FORMAT_YUV420:
      case DRM_FORMAT_YVU420:
        buffer->strides[1] = width * GetFormatBpp(drm_format) / 2;
        buffer->strides[2] = width * GetFormatBpp(drm_format) / 2;
        buffer->offsets[1] = buffer->strides[0] * height;
        buffer->offsets[2] =
            buffer->offsets[1] + (buffer->strides[1] * height / 2);
        break;
      default:
        // Single planar buffer.
        break;
    }
    return buffer;
  }

  const MappedDmaBufInfoCache& GetMappedBufferInfo() const {
    return cbm_->buffer_info_;
  }

 protected:
  CameraBufferManagerImpl* cbm_;

  MockGbm gbm_;
};

TEST_F(CameraBufferManagerImplTest, AllocateTest) {
  const uint32_t kBufferWidth = 1280, kBufferHeight = 720,
                 usage = GRALLOC_USAGE_FORCE_I420;
  buffer_handle_t buffer_handle;
  uint32_t stride;

  // Allocate the buffer.
  EXPECT_CALL(
      gbm_,
      GbmBoCreate(&dummy_device, kBufferWidth, kBufferHeight, DRM_FORMAT_YUV420,
                  GBM_BO_USE_SW_READ_OFTEN | GBM_BO_USE_SW_WRITE_OFTEN))
      .Times(1)
      .WillOnce(Return(&dummy_bo));
  EXPECT_CALL(gbm_, GbmBoGetNumPlanes(&dummy_bo)).Times(1).WillOnce(Return(3));
  for (size_t plane = 0; plane < 3; ++plane) {
    EXPECT_CALL(gbm_, GbmBoGetPlaneFd(&dummy_bo, plane))
        .Times(1)
        .WillOnce(Return(dummy_fd));
    EXPECT_CALL(gbm_, GbmBoGetPlaneOffset(&dummy_bo, plane))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(gbm_, GbmBoGetPlaneStride(&dummy_bo, plane))
        .Times(1)
        .WillOnce(Return(0));
  }
  // Return DRM_FORMAT_MOD_INVALID by default for the mock.
  EXPECT_CALL(gbm_, GbmBoGetModifier(&dummy_bo))
      .Times(1)
      .WillOnce(Return(DRM_FORMAT_MOD_INVALID));
  EXPECT_EQ(cbm_->Allocate(kBufferWidth, kBufferHeight,
                           HAL_PIXEL_FORMAT_YCbCr_420_888, usage,
                           &buffer_handle, &stride),
            0);

  // Lock the buffer.  All the planes should be mapped.
  for (size_t plane = 0; plane < 3; ++plane) {
    EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo, 0, 0, kBufferWidth, kBufferHeight,
                                GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                                A<void**>(), plane))
        .Times(1)
        .WillOnce(Return(dummy_addr));
  }
  struct android_ycbcr ycbcr;
  EXPECT_EQ(cbm_->LockYCbCr(buffer_handle, 0, 0, 0, kBufferWidth, kBufferHeight,
                            &ycbcr),
            0);

  // Unlock the buffer.  All the planes should be unmapped.
  EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo, A<void*>())).Times(3);
  EXPECT_EQ(cbm_->Unlock(buffer_handle), 0);

  // Free the buffer.  The GBM bo should be destroyed and All the FDs should be
  // closed.
  EXPECT_CALL(gbm_, GbmBoDestroy(&dummy_bo)).Times(1);
  EXPECT_CALL(gbm_, Close(dummy_fd)).Times(3);
  EXPECT_EQ(cbm_->Free(buffer_handle), 0);
}

TEST_F(CameraBufferManagerImplTest, LockTest) {
  // Create a dummy buffer.
  const int kBufferWidth = 1280, kBufferHeight = 720;
  auto buffer = CreateBuffer(1, DRM_FORMAT_XBGR8888,
                             HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
                             kBufferWidth, kBufferHeight);
  buffer_handle_t handle = reinterpret_cast<buffer_handle_t>(buffer.get());

  // Register the buffer.
  EXPECT_CALL(gbm_, GbmBoImport(&dummy_device, A<uint32_t>(), A<void*>(),
                                A<uint32_t>()))
      .Times(1)
      .WillOnce(Return(&dummy_bo));
  EXPECT_EQ(cbm_->Register(handle), 0);

  // The call to Lock |handle| should succeed with valid width and height.
  EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo, 0, 0, kBufferWidth, kBufferHeight,
                              GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                              A<void**>(), 0))
      .Times(1)
      .WillOnce(Return(dummy_addr));
  void* addr;
  EXPECT_EQ(cbm_->Lock(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &addr), 0);
  EXPECT_EQ(addr, dummy_addr);

  // And the call to Unlock on |handle| should also succeed.
  EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo, A<void*>())).Times(1);
  EXPECT_EQ(cbm_->Unlock(handle), 0);

  // Now let's Lock |handle| twice.
  EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo, 0, 0, kBufferWidth, kBufferHeight,
                              GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                              A<void**>(), 0))
      .Times(1)
      .WillOnce(Return(dummy_addr));
  EXPECT_EQ(cbm_->Lock(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &addr), 0);
  EXPECT_EQ(addr, dummy_addr);
  // The second Lock call should return the previously mapped virtual address
  // without calling gbm_bo_map2() again.
  EXPECT_EQ(cbm_->Lock(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &addr), 0);
  EXPECT_EQ(addr, dummy_addr);

  // And just Unlock |handle| once, which should not unmap the buffer.
  EXPECT_EQ(cbm_->Unlock(handle), 0);

  // Finally the bo for |handle| should be unmapped and destroyed when we
  // deregister the buffer.
  EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo, A<void*>())).Times(1);
  EXPECT_CALL(gbm_, GbmBoDestroy(&dummy_bo)).Times(1);
  EXPECT_EQ(cbm_->Deregister(handle), 0);

  // The fd of the buffer plane should be closed.
  EXPECT_CALL(gbm_, Close(dummy_fd)).Times(1);
}

TEST_F(CameraBufferManagerImplTest, LockYCbCrTest) {
  constexpr int kBufferWidth = 1280, kBufferHeight = 720;
  {
    // Create a dummy buffer.
    auto buffer =
        CreateBuffer(1, DRM_FORMAT_YUV420, HAL_PIXEL_FORMAT_YCbCr_420_888,
                     kBufferWidth, kBufferHeight);
    buffer_handle_t handle = reinterpret_cast<buffer_handle_t>(buffer.get());

    // Register the buffer.
    EXPECT_CALL(gbm_, GbmBoImport(&dummy_device, A<uint32_t>(), A<void*>(),
                                  A<uint32_t>()))
        .Times(1)
        .WillOnce(Return(&dummy_bo));
    EXPECT_EQ(cbm_->Register(handle), 0);

    // The call to Lock |handle| should succeed with valid width and height.
    for (size_t i = 0; i < 3; ++i) {
      EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo, 0, 0, kBufferWidth, kBufferHeight,
                                  GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                                  A<void**>(), i))
          .Times(1)
          .WillOnce(Return(reinterpret_cast<uint8_t*>(dummy_addr) +
                           buffer->offsets[i]));
    }
    struct android_ycbcr ycbcr;
    EXPECT_EQ(
        cbm_->LockYCbCr(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &ycbcr),
        0);
    EXPECT_EQ(ycbcr.y, dummy_addr);
    EXPECT_EQ(ycbcr.cb,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[1]);
    EXPECT_EQ(ycbcr.cr,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[2]);
    EXPECT_EQ(ycbcr.ystride, buffer->strides[0]);
    EXPECT_EQ(ycbcr.cstride, buffer->strides[1]);
    EXPECT_EQ(ycbcr.chroma_step, 1);

    // And the call to Unlock on |handle| should also succeed.
    EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo, A<void*>())).Times(3);
    EXPECT_EQ(cbm_->Unlock(handle), 0);

    // Now let's Lock |handle| twice.
    for (size_t i = 0; i < 3; ++i) {
      EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo, 0, 0, kBufferWidth, kBufferHeight,
                                  GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                                  A<void**>(), i))
          .Times(1)
          .WillOnce(Return(reinterpret_cast<uint8_t*>(dummy_addr) +
                           buffer->offsets[i]));
    }
    EXPECT_EQ(
        cbm_->LockYCbCr(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &ycbcr),
        0);
    EXPECT_EQ(ycbcr.y, dummy_addr);
    EXPECT_EQ(ycbcr.cb,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[1]);
    EXPECT_EQ(ycbcr.cr,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[2]);
    EXPECT_EQ(ycbcr.ystride, buffer->strides[0]);
    EXPECT_EQ(ycbcr.cstride, buffer->strides[1]);
    EXPECT_EQ(ycbcr.chroma_step, 1);

    // The second LockYCbCr call should return the previously mapped virtual
    // address without calling gbm_bo_map2() again.
    EXPECT_EQ(
        cbm_->LockYCbCr(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &ycbcr),
        0);
    EXPECT_EQ(ycbcr.y, dummy_addr);
    EXPECT_EQ(ycbcr.cb,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[1]);
    EXPECT_EQ(ycbcr.cr,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[2]);
    EXPECT_EQ(ycbcr.ystride, buffer->strides[0]);
    EXPECT_EQ(ycbcr.cstride, buffer->strides[1]);
    EXPECT_EQ(ycbcr.chroma_step, 1);

    // And just Unlock |handle| once, which should not unmap the buffer.
    EXPECT_EQ(cbm_->Unlock(handle), 0);

    // Finally the bo for |handle| should be unmapped and destroyed when we
    // deregister the buffer.
    EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo, A<void*>())).Times(3);
    EXPECT_CALL(gbm_, GbmBoDestroy(&dummy_bo)).Times(1);
    EXPECT_EQ(cbm_->Deregister(handle), 0);

    // The fd of the buffer plane should be closed when |buffer| goes out of
    // scope.
    EXPECT_CALL(gbm_, Close(dummy_fd)).Times(1);
  }

  // Test semi-planar buffers with a list of (DRM_format, chroma_step).
  std::vector<std::tuple<uint32_t, size_t>> formats_to_test = {
      {DRM_FORMAT_NV12, 2}, {DRM_FORMAT_P010, 4}};
  for (const auto& f : formats_to_test) {
    auto buffer =
        CreateBuffer(2, std::get<0>(f), HAL_PIXEL_FORMAT_YCbCr_420_888,
                     kBufferWidth, kBufferHeight);
    buffer_handle_t handle = reinterpret_cast<buffer_handle_t>(buffer.get());

    EXPECT_CALL(gbm_, GbmBoImport(&dummy_device, A<uint32_t>(), A<void*>(),
                                  A<uint32_t>()))
        .Times(1)
        .WillOnce(Return(&dummy_bo));
    EXPECT_EQ(cbm_->Register(handle), 0);

    for (size_t i = 0; i < 2; ++i) {
      EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo, 0, 0, kBufferWidth, kBufferHeight,
                                  GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                                  A<void**>(), i))
          .Times(1)
          .WillOnce(Return(reinterpret_cast<uint8_t*>(dummy_addr) +
                           buffer->offsets[i]));
    }
    struct android_ycbcr ycbcr;
    EXPECT_EQ(
        cbm_->LockYCbCr(handle, 0, 0, 0, kBufferWidth, kBufferHeight, &ycbcr),
        0);
    EXPECT_EQ(ycbcr.y, dummy_addr);
    EXPECT_EQ(ycbcr.cb,
              reinterpret_cast<uint8_t*>(dummy_addr) + buffer->offsets[1]);
    EXPECT_EQ(ycbcr.cr, reinterpret_cast<uint8_t*>(dummy_addr) +
                            buffer->offsets[1] + (std::get<1>(f) / 2));
    EXPECT_EQ(ycbcr.ystride, buffer->strides[0]);
    EXPECT_EQ(ycbcr.cstride, buffer->strides[1]);
    EXPECT_EQ(ycbcr.chroma_step, std::get<1>(f));

    EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo, A<void*>())).Times(2);
    EXPECT_EQ(cbm_->Unlock(handle), 0);

    EXPECT_CALL(gbm_, GbmBoDestroy(&dummy_bo)).Times(1);
    EXPECT_EQ(cbm_->Deregister(handle), 0);

    // The fd of the buffer plane should be closed when |buffer| goes out of
    // scope.
    EXPECT_CALL(gbm_, Close(dummy_fd)).Times(1);
  }
}

TEST_F(CameraBufferManagerImplTest, GetPlaneSizeTest) {
  const int kBufferWidth = 1280, kBufferHeight = 720;

  auto gralloc_buffer = CreateBuffer(0, DRM_FORMAT_XBGR8888,
                                     HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
                                     kBufferWidth, kBufferHeight);
  buffer_handle_t rgbx_handle =
      reinterpret_cast<buffer_handle_t>(gralloc_buffer.get());
  const size_t kRGBXBufferSize =
      kBufferWidth * kBufferHeight * GetFormatBpp(DRM_FORMAT_XBGR8888);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(rgbx_handle, 0),
            kRGBXBufferSize);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(rgbx_handle, 1), 0);

  auto nv12_buffer =
      CreateBuffer(1, DRM_FORMAT_NV21, HAL_PIXEL_FORMAT_YCbCr_420_888,
                   kBufferWidth, kBufferHeight);
  const size_t kNV12Plane0Size =
      kBufferWidth * kBufferHeight * GetFormatBpp(DRM_FORMAT_NV12);
  const size_t kNV12Plane1Size =
      kBufferWidth * kBufferHeight * GetFormatBpp(DRM_FORMAT_NV12) / 2;
  buffer_handle_t nv12_handle =
      reinterpret_cast<buffer_handle_t>(nv12_buffer.get());
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(nv12_handle, 0),
            kNV12Plane0Size);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(nv12_handle, 1),
            kNV12Plane1Size);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(nv12_handle, 2), 0);

  auto yuv420_buffer =
      CreateBuffer(2, DRM_FORMAT_YUV420, HAL_PIXEL_FORMAT_YCbCr_420_888,
                   kBufferWidth, kBufferHeight);
  const size_t kYuv420Plane0Size =
      kBufferWidth * kBufferHeight * GetFormatBpp(DRM_FORMAT_YUV420);
  const size_t kYuv420Plane12Size =
      kBufferWidth * kBufferHeight * GetFormatBpp(DRM_FORMAT_YUV420) / 4;
  buffer_handle_t yuv420_handle =
      reinterpret_cast<buffer_handle_t>(yuv420_buffer.get());
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(yuv420_handle, 0),
            kYuv420Plane0Size);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(yuv420_handle, 1),
            kYuv420Plane12Size);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(yuv420_handle, 2),
            kYuv420Plane12Size);
  EXPECT_EQ(CameraBufferManagerImpl::GetPlaneSize(yuv420_handle, 3), 0);
}

TEST_F(CameraBufferManagerImplTest, IsValidBufferTest) {
  const int kBufferWidth = 1280, kBufferHeight = 720;
  EXPECT_FALSE(CameraBufferManagerImpl::IsValidBuffer(nullptr));
  auto cbh = CreateBuffer(2, DRM_FORMAT_NV12, HAL_PIXEL_FORMAT_YCbCr_420_888,
                          kBufferWidth, kBufferHeight);
  buffer_handle_t handle = reinterpret_cast<buffer_handle_t>(cbh.get());
  EXPECT_TRUE(CameraBufferManagerImpl::IsValidBuffer(handle));

  cbh->magic = ~cbh->magic;
  EXPECT_FALSE(CameraBufferManagerImpl::IsValidBuffer(handle));
}

TEST_F(CameraBufferManagerImplTest, DeregisterTest) {
  // Create two dummy buffers.
  const int kBufferWidth = 1280, kBufferHeight = 720;
  auto buffer1 =
      CreateBuffer(1, DRM_FORMAT_YUV420, HAL_PIXEL_FORMAT_YCbCr_420_888,
                   kBufferWidth, kBufferHeight);
  buffer_handle_t handle1 = reinterpret_cast<buffer_handle_t>(buffer1.get());
  auto buffer2 =
      CreateBuffer(1, DRM_FORMAT_YUV420, HAL_PIXEL_FORMAT_YCbCr_420_888,
                   kBufferWidth, kBufferHeight);
  buffer_handle_t handle2 = reinterpret_cast<buffer_handle_t>(buffer2.get());

  // Register the buffers.
  struct gbm_bo dummy_bo1, dummy_bo2;
  EXPECT_CALL(gbm_, GbmBoImport(&dummy_device, A<uint32_t>(), A<void*>(),
                                A<uint32_t>()))
      .Times(1)
      .WillOnce(Return(&dummy_bo1));
  EXPECT_EQ(cbm_->Register(handle1), 0);
  EXPECT_CALL(gbm_, GbmBoImport(&dummy_device, A<uint32_t>(), A<void*>(),
                                A<uint32_t>()))
      .Times(1)
      .WillOnce(Return(&dummy_bo2));
  EXPECT_EQ(cbm_->Register(handle2), 0);

  // Lock both buffers
  struct android_ycbcr ycbcr;
  for (size_t i = 0; i < 3; ++i) {
    EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo1, 0, 0, kBufferWidth, kBufferHeight,
                                GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                                A<void**>(), i))
        .Times(1);
  }
  EXPECT_EQ(
      cbm_->LockYCbCr(handle1, 0, 0, 0, kBufferWidth, kBufferHeight, &ycbcr),
      0);
  for (size_t i = 0; i < 3; ++i) {
    EXPECT_CALL(gbm_, GbmBoMap2(&dummy_bo2, 0, 0, kBufferWidth, kBufferHeight,
                                GBM_BO_TRANSFER_READ_WRITE, A<uint32_t*>(),
                                A<void**>(), i))
        .Times(1);
  }
  EXPECT_EQ(
      cbm_->LockYCbCr(handle2, 0, 0, 0, kBufferWidth, kBufferHeight, &ycbcr),
      0);

  // There should be six mapped planes.
  EXPECT_EQ(GetMappedBufferInfo().size(), 6);

  // Deregister one buffer should only delete three mapped planes.
  EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo1, A<void*>())).Times(3);
  EXPECT_CALL(gbm_, GbmBoDestroy(&dummy_bo1)).Times(1);
  EXPECT_EQ(cbm_->Deregister(handle1), 0);
  EXPECT_EQ(GetMappedBufferInfo().size(), 3);

  EXPECT_CALL(gbm_, GbmBoUnmap(&dummy_bo2, A<void*>())).Times(3);
  EXPECT_CALL(gbm_, GbmBoDestroy(&dummy_bo2)).Times(1);
  EXPECT_EQ(cbm_->Deregister(handle2), 0);
  EXPECT_EQ(GetMappedBufferInfo().size(), 0);
}

}  // namespace tests

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
