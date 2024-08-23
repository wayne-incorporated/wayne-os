/*
 * Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef IMAGE_H
#define IMAGE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <png.h>

#include "fb.h"

#define HIRES_THRESHOLD_HR 2048
#define HIRES_THRESHOLD_VR 2048
#define MAX_SCALE_FACTOR 100

typedef struct _image_t image_t;

image_t* image_create();
void image_set_filename(image_t* image, char* filename);
char* image_get_filename(image_t* image);
void image_set_offset(image_t* image, int32_t offset_x, int32_t offset_y);
void image_set_location(image_t* image, uint32_t location_x, uint32_t location_y);
void image_set_scale(image_t* image, uint32_t scale);
int image_load_image_from_file(image_t* image);
int image_show(image_t* image, fb_t* fb);
void image_release(image_t* image);
void image_destroy(image_t* image);
int image_is_hires(fb_t* fb);
int32_t image_get_auto_scale(fb_t* fb);

#endif
