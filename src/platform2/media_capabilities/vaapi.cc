// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_capabilities/vaapi.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <va/va.h>
#include <va/va_drm.h>
#include <va/va_str.h>

#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>
#include <base/posix/eintr_wrapper.h>
#include "media_capabilities/common.h"

#define VA_LOG_ASSERT(va_error, function)     \
  LOG_ASSERT((va_error) == VA_STATUS_SUCCESS) \
      << function << " failed, VA error: " << vaErrorStr(va_error);

namespace {
Profile VAProfileToProfile(VAProfile va_profile) {
  switch (va_profile) {
    case VAProfileH264ConstrainedBaseline:
      // VAProfileH264Baseline is deprecated in <va/va.h> since libva 2.0.0.
      // https://github.com/intel/libva/commit/6f69256f8ccc9a73c0b196ab77ac69ab1f4f33c2
      // No VA-API driver supports Baseline specific coding tools (ASO, FMO and
      // redundant slices). We regard ConstrainedBaseline as Baseline because
      // encoding ConstrainedBaseline can be regarded as encoding Baseline
      // stream, and since it is rare that the three coding tools are used, most
      // Baseline streams would be ConstrainedBaseline streams.
      return Profile::kH264Baseline;
    case VAProfileH264Main:
      return Profile::kH264Main;
    case VAProfileH264High:
      return Profile::kH264High;
    case VAProfileVP8Version0_3:
      return Profile::kVP8;
    case VAProfileVP9Profile0:
      return Profile::kVP9Profile0;
    case VAProfileVP9Profile2:
      return Profile::kVP9Profile2;
    case VAProfileJPEGBaseline:
      return Profile::kJPEG;
    case VAProfileAV1Profile0:
      return Profile::kAV1Main;
    default:
      return Profile::kNone;
  }
}

Subsampling VARtFormatToSubsampling(uint32_t va_rt_format) {
  switch (va_rt_format) {
    case VA_RT_FORMAT_YUV420:
    case VA_RT_FORMAT_YUV420_10:
      return Subsampling::kYUV420;
    case VA_RT_FORMAT_YUV422:
      return Subsampling::kYUV422;
    case VA_RT_FORMAT_YUV444:
      return Subsampling::kYUV444;
    default:
      LOG(FATAL) << "Unexpected va_rt_format: " << va_rt_format;
      return Subsampling::kNone;
  }
}

std::vector<VAEntrypoint> GetVAEntrypoints(Profile profile, bool decode) {
  if (decode)
    return {VAEntrypointVLD};
  switch (profile) {
    case Profile::kH264Baseline:
    case Profile::kH264Main:
    case Profile::kH264High:
    case Profile::kVP8:
    case Profile::kVP9Profile0:
    case Profile::kVP9Profile2:
    case Profile::kAV1Main:
      return {VAEntrypointEncSlice, VAEntrypointEncSliceLP};
    case Profile::kJPEG:
      return {VAEntrypointEncPicture};
    case Profile::kNone:
    default:
      LOG(FATAL) << "Unexpected profile: " << static_cast<int32_t>(profile);
      return {};
  }
}

// Returns the RT formats that we care about for a given codec.
std::vector<uint32_t> GetVARTFormats(Profile profile, bool decode) {
  switch (profile) {
    case Profile::kH264Baseline:
    case Profile::kH264Main:
    case Profile::kH264High:
    case Profile::kVP8:
    case Profile::kVP9Profile0:
      return {VA_RT_FORMAT_YUV420};
    case Profile::kJPEG:
      if (decode)
        return {VA_RT_FORMAT_YUV420, VA_RT_FORMAT_YUV422, VA_RT_FORMAT_YUV444};
      else
        return {VA_RT_FORMAT_YUV420};
    case Profile::kVP9Profile2:
      return {VA_RT_FORMAT_YUV420_10};
    case Profile::kAV1Main:
      return {VA_RT_FORMAT_YUV420, VA_RT_FORMAT_YUV420_10};
    case Profile::kNone:
    default:
      LOG(FATAL) << "Unexpected profile: " << static_cast<int32_t>(profile);
      return {VA_RT_FORMAT_YUV420};
  }
}

ColorDepth GetColorDepth(uint32_t va_rt_format) {
  return va_rt_format == VA_RT_FORMAT_YUV420_10 ? ColorDepth::k10bit
                                                : ColorDepth::k8bit;
}

uint32_t GetSupportedVARTFormat(VADisplay va_display,
                                VAProfile va_profile,
                                VAEntrypoint entrypoint) {
  VAConfigAttrib attrib{};
  attrib.type = VAConfigAttribRTFormat;
  VAStatus va_res =
      vaGetConfigAttributes(va_display, va_profile, entrypoint, &attrib, 1);
  VA_LOG_ASSERT(va_res, "vaGetConfigAttributes");
  LOG_IF(FATAL, attrib.value == VA_ATTRIB_NOT_SUPPORTED)
      << "VAConfigAttribRTFormat is not supported, va_profile"
      << vaProfileStr(va_profile)
      << ", va_entrypoint=" << vaEntrypointStr(entrypoint);
  return attrib.value;
}

std::vector<VAEntrypoint> GetSupportedVAEntrypoints(VADisplay va_display,
                                                    VAProfile va_profile) {
  const int max_entrypoints = vaMaxNumEntrypoints(va_display);
  LOG_IF(FATAL, max_entrypoints <= 0)
      << "vaMaxNumEntrypoints() returns an invalid value, " << max_entrypoints;

  std::vector<VAEntrypoint> supported_entrypoints(max_entrypoints);
  int num_supported_entrypoints = 0;
  VAStatus va_res = vaQueryConfigEntrypoints(va_display, va_profile,
                                             supported_entrypoints.data(),
                                             &num_supported_entrypoints);
  VA_LOG_ASSERT(va_res, "vaQueryConfigEntryPoints");
  LOG_IF(FATAL, num_supported_entrypoints <= 0 ||
                    num_supported_entrypoints > max_entrypoints)
      << "Invalid number of entrypoints: " << num_supported_entrypoints;

  supported_entrypoints.resize(num_supported_entrypoints);
  return supported_entrypoints;
}

std::pair<int, int> GetMaxResolution(VADisplay va_display,
                                     VAProfile va_profile,
                                     VAEntrypoint va_entrypoint,
                                     uint32_t va_rt_format) {
  VAConfigAttrib attrib{};
  attrib.type = VAConfigAttribRTFormat;
  // To keep a consistency with the chrome implementation, we set either YUV420
  // and YUV420_10. TODO(b/188486492): Set to |va_rt_format| once the chrome
  // implementation is fixed.
  attrib.value = va_profile == VAProfileVP9Profile2 ? VA_RT_FORMAT_YUV420_10
                                                    : VA_RT_FORMAT_YUV420;

  VAConfigID va_config_id = VA_INVALID_ID;
  VAStatus va_res = vaCreateConfig(va_display, va_profile, va_entrypoint,
                                   &attrib, 1, &va_config_id);
  VA_LOG_ASSERT(va_res, "vaCreateConfig");
  unsigned int num_surface_attribs;
  va_res = vaQuerySurfaceAttributes(va_display, va_config_id, nullptr,
                                    &num_surface_attribs);
  VA_LOG_ASSERT(va_res, "vaQuerySurfaceAttributes");
  LOG_IF(FATAL, num_surface_attribs == 0)
      << "vaQuerySurfaceAttributes: num_surface_attribs is zero";

  std::vector<VASurfaceAttrib> va_surface_attribs(num_surface_attribs);
  va_res =
      vaQuerySurfaceAttributes(va_display, va_config_id,
                               va_surface_attribs.data(), &num_surface_attribs);
  VA_LOG_ASSERT(va_res, "vaQuerySurfaceAttributes");
  std::pair<int, int> max_resolution(0, 0);
  for (const VASurfaceAttrib& attrib : va_surface_attribs) {
    switch (attrib.type) {
      case VASurfaceAttribMaxWidth:
        max_resolution.first = base::strict_cast<int>(attrib.value.value.i);
        break;
      case VASurfaceAttribMaxHeight:
        max_resolution.second = base::strict_cast<int>(attrib.value.value.i);
        break;
      default:
        break;
    }
  }
  return max_resolution;
}

std::vector<Capability> GetCapabilitiesInVADisplay(VADisplay va_display) {
  const int max_profiles = vaMaxNumProfiles(va_display);
  LOG_IF(FATAL, max_profiles <= 0)
      << "vaMaxNumProfiles() returns an invalid value, " << max_profiles;

  std::vector<VAProfile> supported_profiles(max_profiles);
  int num_supported_profiles = 0;
  VAStatus va_res = vaQueryConfigProfiles(va_display, supported_profiles.data(),
                                          &num_supported_profiles);
  VA_LOG_ASSERT(va_res, "vaQueryConfigProfiles");
  LOG_IF(FATAL,
         num_supported_profiles <= 0 || num_supported_profiles > max_profiles)
      << "Invalid number of profiles: " << num_supported_profiles;
  supported_profiles.resize(num_supported_profiles);

  std::vector<Capability> capabilities;
  for (const VAProfile va_profile : supported_profiles) {
    const Profile profile = VAProfileToProfile(va_profile);
    if (profile == Profile::kNone)  // Uninteresting |va_profile|.
      continue;

    auto supported_entrypoints =
        GetSupportedVAEntrypoints(va_display, va_profile);
    for (bool decode : {true, false}) {
      for (VAEntrypoint va_entrypoint : GetVAEntrypoints(profile, decode)) {
        if (!base::Contains(supported_entrypoints, va_entrypoint))
          continue;
        const uint32_t supported_va_rt_format =
            GetSupportedVARTFormat(va_display, va_profile, va_entrypoint);
        for (uint32_t va_rt_format : GetVARTFormats(profile, decode)) {
          if (!(supported_va_rt_format & va_rt_format))
            continue;
          std::pair<int, int> max_resolution = GetMaxResolution(
              va_display, va_profile, va_entrypoint, va_rt_format);
          for (const Resolution resolution :
               GetInterestingResolutionsUpTo(max_resolution)) {
            capabilities.push_back(
                Capability(profile, decode, resolution,
                           VARtFormatToSubsampling(va_rt_format),
                           GetColorDepth(va_rt_format)));
          }
        }
      }
    }
  }
  return capabilities;
}
}  // namespace

std::vector<Capability> DetectVaapiCapabilities() {
  const char* kDriRenderNode0Path = "/dev/dri/renderD128";
  LOG_IF(FATAL, !base::PathExists(base::FilePath(kDriRenderNode0Path)))
      << kDriRenderNode0Path << " doesn't exist";
  base::ScopedFD fd(
      HANDLE_EINTR(open(kDriRenderNode0Path, O_RDWR | O_CLOEXEC)));
  LOG_IF(FATAL, !fd.is_valid()) << "Failed to open " << kDriRenderNode0Path;

  VADisplay va_display = vaGetDisplayDRM(fd.get());
  LOG_IF(FATAL, !vaDisplayIsValid(va_display)) << "VADisplay is invalid";

  int major_version = 0;
  int minor_version = 0;
  VAStatus va_res = vaInitialize(va_display, &major_version, &minor_version);
  VA_LOG_ASSERT(va_res, "vaInitialize");

  auto capabilities = GetCapabilitiesInVADisplay(va_display);
  va_res = vaTerminate(va_display);
  VA_LOG_ASSERT(va_res, "vaTerminate");
  return capabilities;
}
