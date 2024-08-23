/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef FB_H
#define FB_H

#include "drm.h"

typedef struct {
	int32_t width;
	int32_t height;
	int32_t pitch;
	int32_t scaling;
	int32_t size;
	int32_t rotation; // DRM_MODE_ROTATE_*
} buffer_properties_t;

typedef struct {
	int32_t count;
	uint64_t map_offset;
	uint32_t* map;
} fb_lock_t;

typedef struct {
	drm_t *drm;
	buffer_properties_t buffer_properties;
	fb_lock_t lock;
	uint32_t buffer_handle;
	uint32_t fb_id;
} fb_t;

typedef struct {
	fb_t *fb;
	int32_t start_x, start_y;
	uint32_t w, h;
	uint32_t x, y;
	int32_t max_x, max_y;
	uint32_t pitch_div_4;
	int32_t m[2][3];
} fb_stepper_t;

fb_t* fb_init(void);
void fb_close(fb_t* fb);
int32_t fb_setmode(fb_t* fb);
int fb_buffer_init(fb_t* fb);
void fb_buffer_destroy(fb_t* fb);
uint32_t* fb_lock(fb_t* fb);
void fb_unlock(fb_t* fb);
int32_t fb_getwidth(fb_t* fb);
int32_t fb_getheight(fb_t* fb);
int32_t fb_getscaling(fb_t* fb);
bool fb_stepper_init(fb_stepper_t *s, fb_t *fb, int32_t x, int32_t y, uint32_t width, uint32_t height);

bool static inline fb_stepper_step_x(fb_stepper_t *s, uint32_t rgba)
{
	int32_t x = s->start_x + s->x;
	int32_t y = s->start_y + s->y;
	int32_t p;

	if (x >= 0 && x < s->max_x
	    && y >= 0 && y < s->max_y) {
		p = (x * s->m[0][0] + y * s->m[0][1] + s->m[0][2])
		  + (x * s->m[1][0] + y * s->m[1][1] + s->m[1][2]) * s->pitch_div_4;
		s->fb->lock.map[p] = rgba;
	}

	s->x++;
	if (s->x >= s->w) {
		s->x = 0;
		return false;
	}
	return true;
}

bool inline fb_stepper_step_y(fb_stepper_t *s)
{
	s->y++;
	return s->y < s->h;
}

#endif
