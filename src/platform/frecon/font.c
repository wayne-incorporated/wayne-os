/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>

#include "font.h"
#include "glyphs.h"
#include "util.h"

#define UNICODE_REPLACEMENT_CHARACTER_CODE_POINT 0xFFFD

static int font_scaling = 0;
static int glyph_size = GLYPH_BYTES_PER_ROW * GLYPH_HEIGHT;
static uint8_t* prescaled_glyphs = NULL;
static int font_ref = 0;

static uint8_t get_bit(const uint8_t* buffer, int bit_offset)
{
	return (buffer[bit_offset / 8] >> (7 - (bit_offset % 8))) & 0x1;
}

static void set_bit(uint8_t* buffer, int bit_offset)
{
	buffer[bit_offset / 8] |= (0x1 << (7 - (bit_offset % 8)));
}

static uint8_t glyph_pixel(const uint8_t* glyph, int x, int y)
{
	if (x < 0 || x >= GLYPH_WIDTH || y < 0 || y >= GLYPH_HEIGHT)
		return 0;
	return get_bit(&glyph[y * GLYPH_BYTES_PER_ROW], x);
}

static uint8_t scale_pixel(uint32_t neighbors, int sx, int sy, int scaling)
{
	/* Bitmasks of neighbor pixels */
	enum {
		NW = (1 << 8),
		N  = (1 << 7),
		NE = (1 << 6),
		W  = (1 << 5),
		C  = (1 << 4),
		E  = (1 << 3),
		SW = (1 << 2),
		S  = (1 << 1),
		SE = (1 << 0),
	};

	/*
	 * Scale a pixel by a factor of |scaling|, based on the colors of the
	 *   center pixel and the eight neighbor pixels on a 3x3 grid:
	 *
	 *       NW | N | NE
	 *       ---+---+---
	 *        W | C | E
	 *       ---+---+---
	 *       SW | S | SE
	 *
	 * If the center pixel (C) is 1:
	 *   Return 0 if a side pixel (N,W,E,S) and a corner pixel (NW,NE,SW,SE)
	 *     disconnected from each other are both 1, and (sx, sy) falls on
	 *     the corner of the center pixel furthest away from them, and all
	 *     other pixels on the side of that corner are 0;
	 *   Otherwise, return 1.
	 *
	 * If the center pixel is 0:
	 *   Return 0 if all four side pixels are 1;
	 *   Otherwise, return 1 if two adjacent side pixels are 1, and
	 *     (sx, sy) falls inside the isosceles right triangle adjoining
	 *     these two neighbor pixels and with legs of length |scaling - 1|,
	 *     and either the corner pixel next to both side pixels is 0, or
	 *     the other two corner pixels next to these side pixels are both 0.
	 */
	if (neighbors & C) {
		return !((sx == 0 && sy == 0 &&
				((neighbors & (S|SW|W|NW|N|NE)) == (S|NE) ||
				(neighbors & (E|NE|N|NW|W|SW)) == (E|SW))) ||
			(sx == scaling - 1 && sy == 0 &&
				((neighbors & (W|NW|N|NE|E|SE)) == (W|SE) ||
				(neighbors & (S|SE|E|NE|N|NW)) == (S|NW))) ||
			(sx == 0 && sy == scaling - 1 &&
				((neighbors & (N|NW|W|SW|S|SE)) == (N|SE) ||
				(neighbors & (E|SE|S|SW|W|NW)) == (E|NW))) ||
			(sx == scaling - 1 && sy == scaling - 1 &&
				((neighbors & (N|NE|E|SE|S|SW)) == (N|SW) ||
				(neighbors & (W|SW|S|SE|E|NE)) == (W|NE))));
	} else {
		return ((neighbors & (N|W|E|S)) != (N|W|E|S) &&
			((sx < sy &&
				(neighbors & (W|S)) == (W|S) &&
				((neighbors & SW) == 0 ||
				(neighbors & (NW|SE)) == 0)) ||
			(sy < sx &&
				(neighbors & (N|E)) == (N|E) &&
				((neighbors & NE) == 0 ||
				(neighbors & (NW|SE)) == 0)) ||
			(sx + sy > scaling - 1 &&
				(neighbors & (E|S)) == (E|S) &&
				((neighbors & SE) == 0 ||
				(neighbors & (NE|SW)) == 0)) ||
			(sx + sy < scaling - 1 &&
				(neighbors & (N|W)) == (N|W) &&
				((neighbors & NW) == 0 ||
				(neighbors & (NE|SW)) == 0))));
	}
}

static void scale_glyph(uint8_t* dst, const uint8_t* src, int scaling)
{
	for (int y = 0; y < GLYPH_HEIGHT; y++) {
		for (int x = 0; x < GLYPH_WIDTH; x++) {
			uint32_t neighbors = 0;
			for (int dy = -1; dy <= 1; dy++) {
				for (int dx = -1; dx <= 1; dx++) {
					neighbors <<= 1;
					neighbors |= glyph_pixel(
						src, x + dx, y + dy);
				}
			}
			for (int sy = 0; sy < scaling; sy++) {
				uint8_t* dst_row = &dst[(y * scaling + sy) *
					GLYPH_BYTES_PER_ROW * scaling];
				for (int sx = 0; sx < scaling; sx++) {
					if (scale_pixel(neighbors, sx, sy,
							scaling)) {
						set_bit(dst_row,
							x * scaling + sx);
					}
				}
			}
		}
	}
}

static void prescale_font(int scaling)
{
	int glyph_count = sizeof(glyphs) / (GLYPH_BYTES_PER_ROW * GLYPH_HEIGHT);

	glyph_size = GLYPH_BYTES_PER_ROW * GLYPH_HEIGHT * scaling * scaling;
	if (!prescaled_glyphs)
		prescaled_glyphs = (uint8_t*)calloc(glyph_count, glyph_size);
	for (int i = 0; i < glyph_count; i++) {
		const uint8_t* src_glyph = glyphs[i];
		uint8_t* dst_glyph = &prescaled_glyphs[i * glyph_size];
		scale_glyph(dst_glyph, src_glyph, scaling);
	}
}

void font_init(int scaling)
{
	if (font_ref == 0) {
		font_scaling = scaling;
		if (scaling > 1) {
			prescale_font(scaling);
		}
	}
	font_ref++;
}

void font_free()
{
	font_ref--;
	if (font_ref == 0) {
		if (prescaled_glyphs) {
			free(prescaled_glyphs);
			prescaled_glyphs = NULL;
		}
	}
}

void font_get_size(uint32_t* char_width, uint32_t* char_height)
{
	*char_width = GLYPH_WIDTH * font_scaling;
	*char_height = GLYPH_HEIGHT * font_scaling;
}


int font_get_scaling()
{
	return font_scaling;
}

void font_fillchar(fb_t *fb, int dst_char_x, int dst_char_y,
		   uint32_t front_color, uint32_t back_color)
{
	fb_stepper_t s;

	fb_stepper_init(&s,
			fb,
			dst_char_x * GLYPH_WIDTH * font_scaling,
			dst_char_y * GLYPH_HEIGHT * font_scaling,
			GLYPH_WIDTH * font_scaling,
			GLYPH_HEIGHT * font_scaling);

	do {
		do {
		} while (fb_stepper_step_x(&s, back_color));
	} while (fb_stepper_step_y(&s));
}

void font_render(fb_t *fb, int dst_char_x, int dst_char_y,
		 uint32_t ch, uint32_t front_color,
		 uint32_t back_color)
{
	int32_t glyph_index = code_point_to_glyph_index(ch);
	fb_stepper_t s;

	if (glyph_index < 0) {
		glyph_index = code_point_to_glyph_index(
			UNICODE_REPLACEMENT_CHARACTER_CODE_POINT);
		if (glyph_index < 0) {
			return;
		}
	}

	fb_stepper_init(&s,
			fb,
			dst_char_x * GLYPH_WIDTH * font_scaling,
			dst_char_y * GLYPH_HEIGHT * font_scaling,
			GLYPH_WIDTH * font_scaling,
			GLYPH_HEIGHT * font_scaling);

	const uint8_t* glyph;
	if (font_scaling == 1) {
		glyph = glyphs[glyph_index];
	} else {
		glyph = &prescaled_glyphs[glyph_index * glyph_size];
	}

	do {
		const uint8_t* src_row =
			&glyph[s.y * GLYPH_BYTES_PER_ROW * font_scaling];
		do {
		} while (fb_stepper_step_x(&s, get_bit(src_row, s.x) ? front_color : back_color));
	} while (fb_stepper_step_y(&s));
}
