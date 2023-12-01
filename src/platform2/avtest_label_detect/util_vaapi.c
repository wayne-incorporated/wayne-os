// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <va/va.h>
#include <va/va_drm.h>
#include <va/va_prot.h>

#include "label_detect.h"

/* Returns true if given VA profile |va_profile| has |entrypoint| and the entry
 * point supports given raw |format|.
 */
static bool has_vaapi_entrypoint(VADisplay va_display,
                                 VAProfile va_profile,
                                 VAEntrypoint entrypoint,
                                 unsigned int format) {
  VAStatus va_res;
  VAConfigAttrib attrib = {VAConfigAttribRTFormat, 0};
  va_res =
      vaGetConfigAttributes(va_display, va_profile, entrypoint, &attrib, 1);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaGetConfigAttributes failed (%d)\n", va_res);
    return false;
  }

  return attrib.value & format;
}

/* Returns true if the current platform supports at least one of the
 * |required_profiles| and |entrypoint| for that profile supports given raw
 * |format|.
 */
static bool match_vaapi_capabilities(VADisplay va_display,
                                     const VAProfile* required_profiles,
                                     VAEntrypoint entrypoint,
                                     unsigned int format) {
  int i;
  bool found = false;
  int num_supported_profiles;
  VAStatus va_res;
  VAProfile* profiles;
  int max_profiles = vaMaxNumProfiles(va_display);
  /* If no profiles are supported do not proceed further */
  if (max_profiles <= 0) {
    TRACE("vaMaxNumProfiles returns %d \n ", max_profiles);
    return false;
  }

  profiles = (VAProfile*)alloca(sizeof(VAProfile) * max_profiles);
  if (!profiles) {
    TRACE("alloca failed\n");
    return false;
  }
  va_res = vaQueryConfigProfiles(va_display, profiles, &num_supported_profiles);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaQueryConfigProfiles failed (%d)\n", va_res);
    return false;
  }
  for (i = 0; i < num_supported_profiles; i++) {
    int j;
    VAProfile profile = profiles[i];
    TRACE("supported profile: %d\n", profile);
    for (j = 0; required_profiles[j] != VAProfileNone; j++) {
      if (required_profiles[j] == profile &&
          has_vaapi_entrypoint(va_display, profile, entrypoint, format)) {
        found = true;
        /* continue the loop in order to output all supported profiles */
      }
    }
  }
  return found;
}

/* Returns true if libva supports any given profiles. And that profile has said
 * entrypoint with format.
 */
bool is_vaapi_support_formats(int fd,
                              const VAProfile* profiles,
                              VAEntrypoint entrypoint,
                              unsigned int format) {
  bool found = false;
  VAStatus va_res;
  VADisplay va_display;
  int major_version, minor_version;

  va_display = vaGetDisplayDRM(fd);
  if (!vaDisplayIsValid(va_display)) {
    TRACE("vaGetDisplay returns invalid display\n");
    return false;
  }

  va_res = vaInitialize(va_display, &major_version, &minor_version);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaInitialize failed\n");
    return false;
  }

  if (match_vaapi_capabilities(va_display, profiles, entrypoint, format))
    found = true;

  vaTerminate(va_display);

  return found;
}

/* Returns true if |entrypoint| is supported. */
static bool is_entrypoint_supported(VADisplay va_display,
                                    VAProfile va_profile,
                                    VAEntrypoint entrypoint) {
  bool result = false;
  int max_entrypoints = vaMaxNumEntrypoints(va_display);
  VAEntrypoint* supported_entrypoints =
      malloc(max_entrypoints * sizeof(VAEntrypoint));
  int num_supported_entrypoints;
  VAStatus va_res =
      vaQueryConfigEntrypoints(va_display, va_profile, supported_entrypoints,
                               &num_supported_entrypoints);

  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaQueryConfigEntrypoints failed (%d)\n", va_res);
    goto finish;
  }
  if (num_supported_entrypoints < 0 ||
      num_supported_entrypoints > max_entrypoints) {
    TRACE("vaQueryConfigEntrypoints returned: %d\n", num_supported_entrypoints);
    goto finish;
  }

  for (int i = 0; i < num_supported_entrypoints; i++) {
    if (supported_entrypoints[i] == entrypoint) {
      result = true;
      break;
    }
  }

finish:
  free(supported_entrypoints);
  return result;
}

/* Returns true if |required_attribs| are supported. */
static bool are_attribs_supported(VADisplay va_display,
                                  VAProfile va_profile,
                                  VAEntrypoint entrypoint,
                                  const VAConfigAttrib* required_attribs,
                                  int num_required_attribs) {
  bool result = false;
  VAConfigAttrib* attribs =
      malloc(sizeof(VAConfigAttrib) * num_required_attribs);
  memcpy(attribs, required_attribs, sizeof(*attribs) * num_required_attribs);
  for (int i = 0; i < num_required_attribs; i++) {
    attribs[i].value = 0;
  }

  VAStatus va_res = vaGetConfigAttributes(va_display, va_profile, entrypoint,
                                          attribs, num_required_attribs);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaGetConfigAttributes failed (%d)\n", va_res);
    goto finish;
  }

  for (int i = 0; i < num_required_attribs; i++) {
    if (attribs[i].type != required_attribs[i].type ||
        (attribs[i].value & required_attribs[i].value) !=
            required_attribs[i].value) {
      // Unsupported value.
      goto finish;
    }
  }
  result = true;

finish:
  free(attribs);
  return result;
}

/* Returns true if |required_attribs| are supported. */
bool are_vaapi_attribs_supported(int fd,
                                 VAProfile va_profile,
                                 VAEntrypoint entrypoint,
                                 const VAConfigAttrib* required_attribs,
                                 int num_required_attribs) {
  VAStatus va_res;
  VADisplay va_display;
  int major_version, minor_version;

  va_display = vaGetDisplayDRM(fd);
  if (!vaDisplayIsValid(va_display)) {
    TRACE("vaGetDisplay returns invalid display\n");
    return false;
  }

  va_res = vaInitialize(va_display, &major_version, &minor_version);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaInitialize failed\n");
    return false;
  }

  bool res = are_attribs_supported(va_display, va_profile, entrypoint,
                                   required_attribs, num_required_attribs);

  vaTerminate(va_display);
  return res;
}

/* Returns success or failure of getting resolution. The maximum resolution
 * of a passed profile is returned through arguments. */
static bool get_max_resolution(VADisplay va_display,
                               VAProfile va_profile,
                               VAEntrypoint entrypoint,
                               VAConfigAttrib* required_attribs,
                               int num_required_attribs,
                               int32_t* width,
                               int32_t* height) {
  VAStatus va_res;
  VAConfigID va_config_id;
  VASurfaceAttrib* attrib_list;
  unsigned int num_attribs = 0;
  *width = 0;
  *height = 0;

  va_res = vaCreateConfig(va_display, va_profile, entrypoint, required_attribs,
                          num_attribs, &va_config_id);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaQueryConfigProfiles failed (%d)\n", va_res);
    return false;
  }
  // Calls vaQuerySurfaceAttributes twice. The first time is to get the number
  // of attributes to prepare the space and the second time is to get all
  // attributes.
  va_res =
      vaQuerySurfaceAttributes(va_display, va_config_id, NULL, &num_attribs);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaQuerySurfaceAttributes failed (%d)\n", va_res);
    return false;
  }
  if (!num_attribs) {
    return false;
  }

  attrib_list = malloc(num_attribs * sizeof(VASurfaceAttrib));
  va_res = vaQuerySurfaceAttributes(va_display, va_config_id, attrib_list,
                                    &num_attribs);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaQuerySurfaceAttributes failed (%d)\n", va_res);
    free(attrib_list);
    return false;
  }
  for (unsigned int j = 0; j < num_attribs; j++) {
    VASurfaceAttrib attrib = attrib_list[j];
    if (attrib.type == VASurfaceAttribMaxWidth) {
      *width = attrib.value.value.i;
    } else if (attrib.type == VASurfaceAttribMaxHeight) {
      *height = attrib.value.value.i;
    }
  }
  free(attrib_list);
  return *width > 0 && *height > 0;
}

/* Returns success or failure of getting resolution. The maximum resolution
 * among passed profiles is returned through arguments. */
bool get_vaapi_max_resolution(int fd,
                              const VAProfile* profiles,
                              VAEntrypoint entrypoint,
                              unsigned int format,
                              int32_t* const resolution_width,
                              int32_t* const resolution_height) {
  *resolution_width = 0;
  *resolution_height = 0;

  VAConfigAttrib required_attribs = {VAConfigAttribRTFormat, format};

  VAStatus va_res;
  VADisplay va_display = vaGetDisplayDRM(fd);
  int major_version, minor_version;
  if (!vaDisplayIsValid(va_display)) {
    TRACE("vaGetDisplay returns invalid display\n");
    return false;
  }
  va_res = vaInitialize(va_display, &major_version, &minor_version);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaInitialize failed\n");
    return false;
  }

  for (size_t i = 0; profiles[i] != VAProfileNone; i++) {
    VAProfile va_profile = profiles[i];
    int32_t width = 0;
    int32_t height = 0;
    if (!is_entrypoint_supported(va_display, va_profile, entrypoint)) {
      continue;
    }

    if (!are_attribs_supported(va_display, va_profile, entrypoint,
                               &required_attribs, 1)) {
      continue;
    }

    if (!get_max_resolution(va_display, va_profile, entrypoint,
                            &required_attribs, 1, &width, &height)) {
      TRACE("GetMaxResolution failed for va_profile %d and entrypoint %u\n",
            va_profile, entrypoint);
      continue;
    }

    if (*resolution_width <= width && *resolution_height <= height) {
      *resolution_width = width;
      *resolution_height = height;
    }
  }
  vaTerminate(va_display);
  return *resolution_width > 0 && *resolution_height > 0;
}

// Returns true if this is an AMD Mesa Gallium implementation.
bool is_amd_implementation(int fd) {
  VAStatus va_res;
  VADisplay va_display = vaGetDisplayDRM(fd);
  int major_version, minor_version;
  if (!vaDisplayIsValid(va_display)) {
    TRACE("vaGetDisplay returns invalid display\n");
    return false;
  }
  va_res = vaInitialize(va_display, &major_version, &minor_version);
  if (va_res != VA_STATUS_SUCCESS) {
    TRACE("vaInitialize failed\n");
    return false;
  }
  const char* va_vendor_string = vaQueryVendorString(va_display);
  bool res =
      va_vendor_string &&
      strstr(va_vendor_string, "Mesa Gallium driver") == va_vendor_string;
  vaTerminate(va_display);
  return res;
}