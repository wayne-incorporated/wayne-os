/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/test_support/gl_test_fixture.h"

namespace cros {

void FillTestPattern(buffer_handle_t buffer) {
  CameraBufferManager* buf_mgr = CameraBufferManager::GetInstance();
  int width = CameraBufferManager::GetWidth(buffer);
  int height = CameraBufferManager::GetHeight(buffer);
  uint32_t hal_format = CameraBufferManager::GetHalPixelFormat(buffer);
  if (hal_format == HAL_PIXEL_FORMAT_YCbCr_422_I) {
    void* addr = nullptr;
    CHECK_EQ(buf_mgr->Lock(buffer, 0, 0, 0, width, height, &addr), 0);
    uint32_t* as_uint32 = reinterpret_cast<uint32_t*>(addr);
    size_t pixel_stride =
        CameraBufferManager::GetPlaneStride(buffer, 0) / sizeof(uint32_t);
    int base = 0;
    for (int y = 0; y < height; ++y) {
      base = y * pixel_stride;
      for (int x = 0; x < width; ++x) {
        as_uint32[base + x] = *reinterpret_cast<uint32_t*>(
            GetTestYuyvColor(x, y, width, height).data());
      }
    }
    CHECK_EQ(buf_mgr->Unlock(buffer), 0);
  } else if (hal_format == HAL_PIXEL_FORMAT_RGBX_8888) {
    void* addr = nullptr;
    CHECK_EQ(buf_mgr->Lock(buffer, 0, 0, 0, width, height, &addr), 0);
    uint32_t* as_uint32 = reinterpret_cast<uint32_t*>(addr);
    size_t pixel_stride =
        CameraBufferManager::GetPlaneStride(buffer, 0) / sizeof(uint32_t);
    int base = 0;
    for (int y = 0; y < height; ++y) {
      base = y * pixel_stride;
      for (int x = 0; x < width; ++x) {
        as_uint32[base + x] = *reinterpret_cast<uint32_t*>(
            GetTestRgbaColor(x, y, width, height).data());
      }
    }
    CHECK_EQ(buf_mgr->Unlock(buffer), 0);
  } else if (hal_format == HAL_PIXEL_FORMAT_YCbCr_420_888) {
    android_ycbcr ycbcr = {};
    CHECK_EQ(buf_mgr->LockYCbCr(buffer, 0, 0, 0, width, height, &ycbcr), 0);
    // Fill Y plane. 1 byte per pixel with dimension w x h.
    {
      uint8_t* as_uint8 = reinterpret_cast<uint8_t*>(ycbcr.y);
      size_t pixel_stride =
          CameraBufferManager::GetPlaneStride(buffer, 0) / sizeof(uint8_t);
      int base = 0;
      for (int y = 0; y < height; ++y) {
        base = y * pixel_stride;
        for (int x = 0; x < width; ++x) {
          as_uint8[base + x] = GetTestYuvColor(x, y, width, height)[0];
        }
      }
    }
    // Fill UV plane. 2x2 subsampling with 2 bytes per pixel and dimension
    // (w / 2) x (h / 2).
    {
      uint16_t* as_uint16 = reinterpret_cast<uint16_t*>(ycbcr.cb);
      size_t pixel_stride =
          CameraBufferManager::GetPlaneStride(buffer, 1) / sizeof(uint16_t);
      int base = 0;
      for (int y = 0; y < height / 2; ++y) {
        base = y * pixel_stride;
        for (int x = 0; x < width / 2; ++x) {
          as_uint16[base + x] = *reinterpret_cast<uint16_t*>(
              &GetTestYuvColor(x * 2, y * 2, width, height)[1]);
        }
      }
    }
    CHECK_EQ(buf_mgr->Unlock(buffer), 0);
  } else if (hal_format == HAL_PIXEL_FORMAT_YCBCR_P010) {
    android_ycbcr ycbcr = {};
    CHECK_EQ(buf_mgr->LockYCbCr(buffer, 0, 0, 0, width, height, &ycbcr), 0);
    // Fill Y plane. 2 byte per pixel with dimension w x h.
    {
      uint16_t* as_uint16 = reinterpret_cast<uint16_t*>(ycbcr.y);
      size_t pixel_stride =
          CameraBufferManager::GetPlaneStride(buffer, 0) / sizeof(uint16_t);
      int base = 0;
      for (int y = 0; y < height; ++y) {
        base = y * pixel_stride;
        for (int x = 0; x < width; ++x) {
          as_uint16[base + x] = GetTestYuvColor(x, y, width, height)[0];
          as_uint16[base + x] <<= 8;
        }
      }
    }
    // Fill UV plane. 2x2 subsampling with 4 bytes per pixel and dimension
    // (w / 2) x (h / 2).
    {
      uint32_t* as_uint32 = reinterpret_cast<uint32_t*>(ycbcr.cb);
      size_t pixel_stride =
          CameraBufferManager::GetPlaneStride(buffer, 1) / sizeof(uint32_t);
      int base = 0;
      for (int y = 0; y < height / 2; ++y) {
        base = y * pixel_stride;
        for (int x = 0; x < width / 2; ++x) {
          uint16_t* u = reinterpret_cast<uint16_t*>(as_uint32 + base + x);
          uint16_t* v = u + 1;
          *u = GetTestYuvColor(x * 2, y * 2, width, height)[1];
          *u <<= 8;
          *v = GetTestYuvColor(x * 2, y * 2, width, height)[2];
          *v <<= 8;
        }
      }
    }
    CHECK_EQ(buf_mgr->Unlock(buffer), 0);
  }
}

std::array<uint8_t, 4> GetTestRgbaColor(int x, int y, int width, int height) {
  // Gradient color along the X/Y axes.
  uint8_t R = 255 * x / width;
  uint8_t G = 255 * y / height;
  uint8_t B = 0;
  return std::array<uint8_t, 4>{R, G, B, 255};
}

std::array<uint8_t, 3> GetTestYuvColor(int x, int y, int width, int height) {
  auto rgb = GetTestRgbaColor(x, y, width, height);
  float Y = 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2];
  float U = -0.16874 * rgb[0] - 0.33126 * rgb[1] + 0.5 * rgb[2] + 128;
  float V = 0.5 * rgb[0] - 0.41869 * rgb[1] - 0.08131 * rgb[2] + 128;
  return std::array<uint8_t, 3>{base::checked_cast<uint8_t>(Y),
                                base::checked_cast<uint8_t>(U),
                                base::checked_cast<uint8_t>(V)};
}

std::array<uint8_t, 4> GetTestYuyvColor(int x, int y, int width, int height) {
  auto yuv1 = GetTestYuvColor(x * 2, y, width * 2, height);
  auto yuv2 = GetTestYuvColor(x * 2 + 1, y, width * 2, height);
  return std::array<uint8_t, 4>{yuv1[0], yuv1[1], yuv2[0], yuv1[2]};
}

GlTestFixture::GlTestFixture() {
  // Create EGLContext.
  egl_context_ = EglContext::GetSurfacelessContext();
  if (!egl_context_->IsValid()) {
    LOGF(FATAL) << "Failed to create EGL context";
  }

  // Make current.
  if (!egl_context_->MakeCurrent()) {
    LOGF(FATAL) << "Failed to make display current";
  }
}

void GlTestFixture::DumpInfo() const {
  EglDumpInfo();
  GlDumpInfo();
}

}  // namespace cros
