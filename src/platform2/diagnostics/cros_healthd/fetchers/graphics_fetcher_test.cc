// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/strings/string_split.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/fetchers/graphics_fetcher.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::ByMove;
using ::testing::Return;

// Fake OpenGLES information.
constexpr char kFakeOpenGLESVersion[] = "OpenGL ES 3.2 Mesa 21.0.2";
constexpr char kFakeOpenGLESShadingVersion[] = "OpenGL ES GLSL ES 3.20";
constexpr char kFakeOpenGLESVendor[] = "Intel Open Source Technology Center";
constexpr char kFakeOpenGLESRenderer[] = "Mesa DRI Intel(R) UHD Graphics";
constexpr char kFakeOpenGLESExtensions[] = "ext1 ext2";

// Fake EGL information.
constexpr char kFakeEGLVersion[] = "1.4";
constexpr char kFakeEGLVendor[] = "Mesa Project";
constexpr char kFakeEGLClientApi[] = "OpenGL OpenGL_ES";
constexpr char kFakeEGLExtensions[] = "ext3 ext4";

class MockEglManager final : public EglManager {
 public:
  MockEglManager() = default;
  MockEglManager(const MockEglManager&) = delete;
  MockEglManager& operator=(const MockEglManager&) = delete;
  ~MockEglManager() override = default;

  MOCK_METHOD(mojom::GLESInfoPtr, FetchGLESInfo, (), ());
  MOCK_METHOD(mojom::EGLInfoPtr, FetchEGLInfo, (), ());
};

class GraphicsFetcherTest : public ::testing::Test {
 protected:
  GraphicsFetcherTest() = default;
  GraphicsFetcherTest(const GraphicsFetcherTest&) = delete;
  GraphicsFetcherTest& operator=(const GraphicsFetcherTest&) = delete;

  mojom::GraphicsResultPtr FetchGraphicsInfo(
      std::unique_ptr<EglManager> mock_egl_manager) {
    return graphics_fetcher_.FetchGraphicsInfo(std::move(mock_egl_manager));
  }

 private:
  MockContext mock_context_;
  GraphicsFetcher graphics_fetcher_{&mock_context_};
};

TEST_F(GraphicsFetcherTest, FetchGraphicsInfo) {
  auto gles_info = mojom::GLESInfo::New();
  gles_info->version = kFakeOpenGLESVersion;
  gles_info->shading_version = kFakeOpenGLESShadingVersion;
  gles_info->vendor = kFakeOpenGLESVendor;
  gles_info->renderer = kFakeOpenGLESRenderer;
  auto expected_gles_extensions =
      base::SplitString(kFakeOpenGLESExtensions, " ", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);
  gles_info->extensions = expected_gles_extensions;

  auto egl_info = mojom::EGLInfo::New();
  egl_info->version = kFakeEGLVersion;
  egl_info->vendor = kFakeEGLVendor;
  egl_info->client_api = kFakeEGLClientApi;
  auto expected_egl_extensions =
      base::SplitString(kFakeEGLExtensions, " ", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);
  egl_info->extensions = expected_egl_extensions;

  // Because we shouldn't run the |EglManager::Create()| on the corp machine, so
  // using a mock constructor instead to create the object.
  auto mock_egl_manager = std::make_unique<MockEglManager>();
  EXPECT_CALL(*mock_egl_manager, FetchGLESInfo())
      .WillOnce(Return(ByMove(std::move(gles_info))));
  EXPECT_CALL(*mock_egl_manager, FetchEGLInfo())
      .WillOnce(Return(ByMove(std::move(egl_info))));

  auto result = FetchGraphicsInfo(std::move(mock_egl_manager));
  ASSERT_TRUE(result->is_graphics_info());

  const auto& info = result->get_graphics_info();
  EXPECT_EQ(info->gles_info->version, kFakeOpenGLESVersion);
  EXPECT_EQ(info->gles_info->shading_version, kFakeOpenGLESShadingVersion);
  EXPECT_EQ(info->gles_info->vendor, kFakeOpenGLESVendor);
  EXPECT_EQ(info->gles_info->renderer, kFakeOpenGLESRenderer);
  EXPECT_EQ(info->gles_info->extensions, expected_gles_extensions);

  EXPECT_EQ(info->egl_info->version, kFakeEGLVersion);
  EXPECT_EQ(info->egl_info->vendor, kFakeEGLVendor);
  EXPECT_EQ(info->egl_info->client_api, kFakeEGLClientApi);
  EXPECT_EQ(info->egl_info->extensions, expected_egl_extensions);
}

}  // namespace
}  // namespace diagnostics
