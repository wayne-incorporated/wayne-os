// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "screen-capture-utils/egl_capture.h"

#include <sys/mman.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <EGL/eglplatform.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#include <string>
#include <utility>
#include <vector>

#include "base/strings/string_split.h"
#include "screen-capture-utils/crtc.h"

namespace screenshot {
namespace {

constexpr int kBytesPerPixel = 4;

GLuint LoadShader(const GLenum type, const char* const src) {
  GLuint shader = 0;
  shader = glCreateShader(type);
  CHECK(shader) << "Failed to to create shader";

  glShaderSource(shader, 1, &src, 0);
  glCompileShader(shader);

  GLint compiled = 0;
  glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
  if (compiled != GL_TRUE) {
    GLint log_length;
    glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &log_length);
    std::vector<char> shader_log(log_length);
    glGetShaderInfoLog(shader, log_length, nullptr, shader_log.data());
    CHECK(false) << "Shader failed to compile: " << shader_log.data()
                 << ": program: " << src;
  }

  return shader;
}

GLuint LoadProgram(const GLchar* vert, const GLchar* frag) {
  GLint program = glCreateProgram();
  GLuint vertex_shader = LoadShader(GL_VERTEX_SHADER, vert);
  GLuint frag_shader = LoadShader(GL_FRAGMENT_SHADER, frag);
  glAttachShader(program, vertex_shader);
  glAttachShader(program, frag_shader);
  glLinkProgram(program);

  GLint linked = -1;
  glGetProgramiv(program, GL_LINK_STATUS, &linked);
  if (linked != GL_TRUE) {
    GLint log_length = 0;
    glGetProgramiv(program, GL_INFO_LOG_LENGTH, &log_length);
    std::vector<char> program_log(log_length);
    glGetProgramInfoLog(program, log_length, nullptr, program_log.data());
    CHECK(false) << "GL program failed to link: " << program_log.data();
  }
  glUseProgram(program);
  glUniform1i(glGetUniformLocation(program, "tex"), 0);

  glDeleteProgram(program);
  glDeleteShader(vertex_shader);
  glDeleteShader(frag_shader);
  return program;
}

bool DoesExtensionExist(const char* extension_string, const char* name) {
  std::vector<std::string> extensions = base::SplitString(
      extension_string, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);

  return std::find(extensions.begin(), extensions.end(), std::string(name)) !=
         extensions.end();
}

EGLImageKHR CreateImage(PFNEGLCREATEIMAGEKHRPROC CreateImageKHR,
                        bool import_modifiers_exist,
                        int drm_fd,
                        EGLDisplay display,
                        const drmModeFB2Ptr fb) {
  int num_planes = 0;
  // CreateImageKHR takes its own references to the dma-bufs, so closing the fds
  // at the end of the function is necessary and won't break the returned image.
  std::vector<base::ScopedFD> fds = {};
  for (size_t plane = 0; plane < GBM_MAX_PLANES; plane++) {
    // getfb2() doesn't return the number of planes so get handles
    // and count planes until we find a handle that isn't set
    if (fb->handles[plane] == 0)
      break;

    int fd;
    int ret = drmPrimeHandleToFD(drm_fd, fb->handles[plane], 0, &fd);
    CHECK_EQ(ret, 0) << "drmPrimeHandleToFD failed";
    fds.emplace_back(fd);
    num_planes++;
  }

  CHECK_GT(num_planes, 0);

  std::vector<EGLint> attr_list = {
      EGL_WIDTH,
      static_cast<EGLint>(fb->width),
      EGL_HEIGHT,
      static_cast<EGLint>(fb->height),
      EGL_LINUX_DRM_FOURCC_EXT,
      static_cast<EGLint>(fb->pixel_format),
  };

  for (size_t plane = 0; plane < num_planes; plane++) {
    attr_list.emplace_back(EGL_DMA_BUF_PLANE0_FD_EXT + plane * 3);
    attr_list.emplace_back(fds[plane].get());
    attr_list.emplace_back(EGL_DMA_BUF_PLANE0_OFFSET_EXT + plane * 3);
    attr_list.emplace_back(fb->offsets[plane]);
    attr_list.emplace_back(EGL_DMA_BUF_PLANE0_PITCH_EXT + plane * 3);
    attr_list.emplace_back(fb->pitches[plane]);

    // If DRM_MODE_FB_MODIFIERS is not set, it means the modifiers are
    // determined implicitly in a driver-specific manner. As such we only
    // set the modifier if we got a framebuffer with explicit modifier and
    // an EGL driver that supports explicit modifiers.
    if (import_modifiers_exist && (fb->flags & DRM_MODE_FB_MODIFIERS)) {
      attr_list.emplace_back(EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT + plane * 2);
      attr_list.emplace_back(fb->modifier & 0xfffffffful);
      attr_list.emplace_back(EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT + plane * 2);
      attr_list.emplace_back(fb->modifier >> 32);
    }
  }

  attr_list.emplace_back(EGL_NONE);

  EGLImageKHR image = CreateImageKHR(display, EGL_NO_CONTEXT,
                                     EGL_LINUX_DMA_BUF_EXT, 0, &attr_list[0]);
  CHECK(image != EGL_NO_IMAGE_KHR) << "Failed to create image";

  return image;
}

void WaitVBlank(int fd) {
  drmVBlank vbl;
  memset(&vbl, 0, sizeof vbl);
  vbl.request.type = DRM_VBLANK_RELATIVE;
  vbl.request.sequence = 1;
  drmWaitVBlank(fd, &vbl);
}

}  // namespace

EglDisplayBuffer::EglDisplayBuffer(
    const Crtc* crtc, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
    : crtc_(*crtc),
      x_(x),
      y_(y),
      width_(width),
      height_(height),
      device_(gbm_create_device(crtc_.file().GetPlatformFile())),
      display_(eglGetDisplay(EGL_DEFAULT_DISPLAY)),
      buffer_(width_ * height_ * kBytesPerPixel) {
  CHECK(device_) << "gbm_create_device failed";

  CHECK(display_ != EGL_NO_DISPLAY) << "Could not get EGLDisplay";

  EGLBoolean egl_ret = eglInitialize(display_, NULL, NULL);
  CHECK(egl_ret) << "Could not initialize EGLDisplay";

  const EGLint config_attribs[] = {EGL_SURFACE_TYPE, EGL_DONT_CARE,
                                   EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                                   EGL_NONE};

  const EGLint GLES2[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};

  EGLint num_configs;
  EGLConfig config;

  egl_ret = eglChooseConfig(display_, config_attribs, &config, 1, &num_configs);
  CHECK(egl_ret) << "Could not choose EGLConfig";
  CHECK(num_configs != 0) << "Could not choose an EGL configuration";

  ctx_ = eglCreateContext(display_, config, EGL_NO_CONTEXT, GLES2);
  CHECK(ctx_ != EGL_NO_CONTEXT) << "Could not create EGLContext";

  egl_ret = eglMakeCurrent(display_, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx_);
  CHECK(egl_ret) << "Could not bind context";

  std::string egl_extensions = eglQueryString(display_, EGL_EXTENSIONS);
  CHECK(egl_extensions.find("EGL_KHR_image_base") != std::string::npos)
      << "Missing EGL extension: EGL_KHR_image_base";
  CHECK(egl_extensions.find("EGL_EXT_image_dma_buf_import") !=
        std::string::npos)
      << "Missing EGL extension: EGL_EXT_image_dma_buf_import";

  std::string gl_extensions = (const char*)glGetString(GL_EXTENSIONS);
  CHECK(gl_extensions.find("GL_OES_EGL_image") != std::string::npos)
      << "Missing GL extension: GL_OES_EGL_image";
  CHECK(gl_extensions.find("GL_OES_EGL_image_external") != std::string::npos)
      << "Missing GL extension: GL_OES_EGL_image_external";
  createImageKHR_ =
      (PFNEGLCREATEIMAGEKHRPROC)eglGetProcAddress("eglCreateImageKHR");
  CHECK(createImageKHR_) << "CreateImageKHR not supported";
  destroyImageKHR_ =
      (PFNEGLDESTROYIMAGEKHRPROC)eglGetProcAddress("eglDestroyImageKHR");
  CHECK(destroyImageKHR_) << "DestroyImageKHR not supported";

  const char* extensions = eglQueryString(display_, EGL_EXTENSIONS);
  CHECK(extensions) << "eglQueryString() failed to get egl extensions";
  import_modifiers_exist_ =
      DoesExtensionExist(extensions, "EGL_EXT_image_dma_buf_import_modifiers");

  glGenTextures(1, &output_texture_);
  glBindTexture(GL_TEXTURE_2D, output_texture_);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width_, height_, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, NULL);

  glGenTextures(1, &input_texture_);
  glBindTexture(GL_TEXTURE_EXTERNAL_OES, input_texture_);

  glEGLImageTargetTexture2DOES_ =
      (PFNGLEGLIMAGETARGETTEXTURE2DOESPROC)eglGetProcAddress(
          "glEGLImageTargetTexture2DOES");
  CHECK(glEGLImageTargetTexture2DOES_)
      << "glEGLImageTargetTexture2DOES not supported";

  glGenFramebuffers(1, &fbo_);
  glBindFramebuffer(GL_FRAMEBUFFER, fbo_);

  const GLchar* vert = R"(#version 300 es
out vec2 tex_pos;
uniform vec2 uvs[4];
void main() {
  vec2 pos[4];
  pos[0] = vec2(-1.0, -1.0);
  pos[1] = vec2(1.0, -1.0);
  pos[2] = vec2(-1.0, 1.0);
  pos[3] = vec2(1.0, 1.0);
  gl_Position.xy = pos[gl_VertexID];
  gl_Position.zw = vec2(0.0, 1.0);
  tex_pos = uvs[gl_VertexID];
}
)";

  const GLchar* frag = R"(#version 300 es
#extension GL_OES_EGL_image_external_essl3 : require
precision highp float;
uniform samplerExternalOES tex;
in vec2 tex_pos;
out vec4 fragColor;
void main() {
  fragColor = texture(tex, tex_pos);
}
)";

  GLuint program = LoadProgram(vert, frag);
  uvs_uniform_location_ = glGetUniformLocation(program, "uvs");

  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         output_texture_, 0);

  GLenum fb_status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
  CHECK(fb_status == GL_FRAMEBUFFER_COMPLETE) << "fb did not complete";

  glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
}

EglDisplayBuffer::~EglDisplayBuffer() {
  eglMakeCurrent(display_, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
  glDeleteTextures(1, &input_texture_);
  glDeleteTextures(1, &output_texture_);
  glDeleteFramebuffers(1, &fbo_);
  eglDestroyContext(display_, ctx_);
  eglTerminate(display_);
}

DisplayBuffer::Result EglDisplayBuffer::Capture() {
  WaitVBlank(crtc_.file().GetPlatformFile());

  auto connected_planes = crtc_.GetConnectedPlanes();
  if (connected_planes.empty()) {
    VLOG(3) << "Planes are empty, falling back to copying all";
    EGLImageKHR image =
        CreateImage(createImageKHR_, import_modifiers_exist_,
                    crtc_.file().GetPlatformFile(), display_, crtc_.fb2());

    SetUVRect(/*crop_x=*/0, /*crop_y=*/0,
              /*crop_width=*/static_cast<float>(crtc_.fb2()->width),
              /*crop_height=*/static_cast<float>(crtc_.fb2()->height),
              /*src_width=*/static_cast<float>(crtc_.fb2()->width),
              /*src_height=*/static_cast<float>(crtc_.fb2()->height));
    glViewport(0, 0, width_, height_);
    glEGLImageTargetTexture2DOES_(GL_TEXTURE_EXTERNAL_OES, image);

    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

    destroyImageKHR_(display_, image);
  } else {
    VLOG(3) << "Multiple connected planes.";
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    for (auto& plane : connected_planes) {
      EGLImageKHR image = CreateImage(createImageKHR_, import_modifiers_exist_,
                                      crtc_.file().GetPlatformFile(), display_,
                                      plane.first.get());

      // Handle the plane's crop rectangle.
      SetUVRect(plane.second.crop_x, plane.second.crop_y, plane.second.crop_w,
                plane.second.crop_h,
                /*src_width=*/static_cast<float>(plane.first->width),
                /*src_height=*/static_cast<float>(plane.first->height));

      // TODO(andrescj): Handle rotation.
      glViewport(plane.second.x, plane.second.y, plane.second.w,
                 plane.second.h);

      glEGLImageTargetTexture2DOES_(GL_TEXTURE_EXTERNAL_OES, image);

      glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

      destroyImageKHR_(display_, image);
    }
  }

  glPixelStorei(GL_PACK_ALIGNMENT, 1);
  // TODO(uekawa): potentially improve speed by creating a bo and writing to
  // it instead of reading out.
  glReadPixels(x_, y_, width_, height_, GL_BGRA_EXT, GL_UNSIGNED_BYTE,
               buffer_.data());

  return {
      width_, height_,
      width_ * kBytesPerPixel,            // stride
      static_cast<void*>(buffer_.data())  // buffer
  };
}

void EglDisplayBuffer::SetUVRect(float crop_x,
                                 float crop_y,
                                 float crop_width,
                                 float crop_height,
                                 float src_width,
                                 float src_height) {
  const float uv_left = crop_x / src_width;
  const float uv_right = (crop_x + crop_width) / src_width;
  const float uv_top = crop_y / src_height;
  const float uv_bottom = (crop_y + crop_height) / src_height;
  // |uvs| is an array of 4 vec2s: each pair of elements represents X and Y
  // coordinates.
  GLfloat uvs[] = {
      // clang-format off
      uv_left,  uv_top,
      uv_right, uv_top,
      uv_left,  uv_bottom,
      uv_right, uv_bottom
      // clang-format on
  };
  glUniform2fv(uvs_uniform_location_, 4, uvs);
}

}  // namespace screenshot
