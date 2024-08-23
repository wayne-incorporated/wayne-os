/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef FONT_H
#define FONT_H

#include "fb.h"

void font_init(int scaling);
void font_free();
void font_fillchar(fb_t *fb, int dst_char_x, int dst_char_y,
		   uint32_t front_color, uint32_t back_color);
void font_render(fb_t *fb, int dst_char_x, int dst_char_y,
		 uint32_t ch, uint32_t front_color,
		 uint32_t back_color);
void font_get_size(uint32_t* char_width, uint32_t* char_height);
int font_get_scaling();

#endif
