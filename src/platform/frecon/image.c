/*
 * Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "fb.h"
#include "image.h"
#include "util.h"

typedef union {
	uint32_t* as_pixels;
	png_byte* as_png_bytes;
	char* address;
} layout_t;

struct _image_t {
	char* filename;
	bool use_offset;
	bool use_location;
	int32_t offset_x;
	int32_t offset_y;
	uint32_t location_x;
	uint32_t location_y;
	uint32_t scale;
	uint32_t duration;
	layout_t layout;
	png_uint_32 width;
	png_uint_32 height;
	png_uint_32 pitch;
};

image_t* image_create()
{
	image_t* image;

	image = (image_t*)calloc(1, sizeof(image_t));
	image->scale = 1;
	return image;
}

static void image_rgb(png_struct* png, png_row_info* row_info, png_byte* data)
{
	for (unsigned int i = 0; i < row_info->rowbytes; i+= 4) {
		uint32_t r, g, b, a;
		uint32_t pixel;

		r = data[i + 0];
		g = data[i + 1];
		b = data[i + 2];
		a = data[i + 3];
		pixel = (a << 24) | (r << 16) | (g << 8) | b;
		memcpy(data + i, &pixel, sizeof(pixel));
	}
}

int image_load_image_from_file(image_t* image)
{
	FILE* fp;
	png_struct* png;
	png_info* info;
	png_uint_32 width, height, pitch, row;
	int bpp, color_type, interlace_mthd;
	png_byte** rows;
	int ret = 0;

	if (image->layout.address != NULL)
		return EADDRINUSE;

	fp = fopen(image->filename, "rb");
	if (fp == NULL)
		return errno;

	png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	info = png_create_info_struct(png);

	if (info == NULL)
		return 1;

	png_init_io(png, fp);

	ret = setjmp(png_jmpbuf(png));
	if (ret != 0)
		goto fail;

	png_read_info(png, info);
	png_get_IHDR(png, info, &width, &height, &bpp, &color_type,
			&interlace_mthd, NULL, NULL);

	pitch = 4 * width;

	switch (color_type)
	{
		case PNG_COLOR_TYPE_PALETTE:
			png_set_palette_to_rgb(png);
			break;

		case PNG_COLOR_TYPE_GRAY:
		case PNG_COLOR_TYPE_GRAY_ALPHA:
			png_set_gray_to_rgb(png);
	}

	if (png_get_valid(png, info, PNG_INFO_tRNS))
		png_set_tRNS_to_alpha(png);

	switch (bpp)
	{
		default:
			if (bpp < 8)
				png_set_packing(png);
			break;
		case 16:
			png_set_strip_16(png);
			break;
	}

	if (interlace_mthd != PNG_INTERLACE_NONE)
		png_set_interlace_handling(png);

	png_set_filler(png, 0xff, PNG_FILLER_AFTER);

	png_set_read_user_transform_fn(png, image_rgb);
	png_read_update_info(png, info);

	rows = malloc(height * sizeof(*rows));
	if (!rows) {
		ret = -ENOMEM;
		goto fail;
	}

	image->layout.address = malloc(height * pitch);
	if (!image->layout.address) {
		free(rows);
		ret = -ENOMEM;
		goto fail;
	}

	for (row = 0; row < height; row++)
		rows[row] = &image->layout.as_png_bytes[row * pitch];

	png_read_image(png, rows);
	free(rows);

	image->width = width;
	image->height = height;
	image->pitch = pitch;
	png_read_end(png, info);

fail:
	png_destroy_read_struct(&png, &info, NULL);
	fclose(fp);
	fp = NULL;
	return ret;
}

int image_show(image_t* image, fb_t* fb)
{
	fb_stepper_t s;
	int32_t startx, starty;
	uint32_t w, h;

	if (fb_lock(fb) == NULL)
		return -1;

	if (image->use_offset && image->use_location) {
		LOG(WARNING, "offset and location set, using location");
		image->use_offset = false;
	}

	w = image->width * image->scale;
	h = image->height * image->scale;

	if (image->use_location) {
		startx = image->location_x;
		starty = image->location_y;
	} else {
		startx = (fb_getwidth(fb) - (int32_t)w)/2;
		starty = (fb_getheight(fb) - (int32_t)h)/2;
	}

	if (image->use_offset) {
		startx += image->offset_x * (int32_t)image->scale;
		starty += image->offset_y * (int32_t)image->scale;
	}

	if (!fb_stepper_init(&s, fb, startx, starty, w, h))
		goto done;

	do {
		do {
		} while (fb_stepper_step_x(&s, image->layout.as_pixels[(s.y / image->scale) * (image->pitch >> 2) + (s.x / image->scale)]));
	} while (fb_stepper_step_y(&s));

done:
	fb_unlock(fb);
	return 0;
}

void image_release(image_t* image)
{
	if (image->layout.address != NULL) {
		free(image->layout.address);
		image->layout.address = NULL;
	}
}

void image_destroy(image_t* image)
{
	image_release(image);

	if (image->filename != NULL) {
		free(image->filename);
		image->filename = NULL;
	}

	free(image);
}

void image_set_filename(image_t* image, char* filename)
{
	if (image->filename != NULL)
		free(image->filename);

	image->filename = strdup(filename);
}

char* image_get_filename(image_t* image)
{
	return image->filename;
}

void image_set_offset(image_t* image, int32_t offset_x, int32_t offset_y)
{
	image->offset_x = offset_x;
	image->offset_y = offset_y;

	image->use_offset = true;
}

void image_set_location(image_t* image,
			uint32_t location_x, uint32_t location_y)
{
	image->location_x = location_x;
	image->location_y = location_y;

	image->use_location = true;
}

void image_set_scale(image_t* image, uint32_t scale)
{
	if (scale > MAX_SCALE_FACTOR)
		scale = MAX_SCALE_FACTOR;
	if (scale == 0)
		image->scale = 1;
	else
		image->scale = scale;
}

int image_is_hires(fb_t* fb)
{
	return fb_getwidth(fb) > HIRES_THRESHOLD_HR ||
	       fb_getheight(fb) > HIRES_THRESHOLD_VR;
}

int32_t image_get_auto_scale(fb_t* fb)
{
	if (image_is_hires(fb))
		return 2;
	else
		return 1;
}
