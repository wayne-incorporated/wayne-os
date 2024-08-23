/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dbus.h"
#include "dbus_interface.h"
#include "image.h"
#include "input.h"
#include "main.h"
#include "splash.h"
#include "term.h"
#include "util.h"

// Modified by seongbin@wayne-inc.com
// #define  MAX_SPLASH_IMAGES      (30)
#define  MAX_SPLASH_IMAGES      (300)
#define  MAX_SPLASH_WAITTIME    (8)

typedef struct {
	image_t* image;
	uint32_t duration;
} splash_frame_t;

struct _splash_t {
	int num_images;
	uint32_t clear;
	splash_frame_t image_frames[MAX_SPLASH_IMAGES];
	bool terminated;
	int32_t loop_start;
	int32_t loop_count;
	uint32_t loop_duration;
	uint32_t default_duration;
	int32_t offset_x;
	int32_t offset_y;
	int32_t loop_offset_x;
	int32_t loop_offset_y;
	uint32_t scale;
};


splash_t* splash_init(int pts_fd)
{
	splash_t* splash;

	splash = (splash_t*)calloc(1, sizeof(splash_t));
	if (!splash)
		return NULL;

	term_create_splash_term(pts_fd);
	splash->loop_start = -1;
	splash->loop_count = -1;
	splash->default_duration = 25;
	splash->loop_duration = 25;
	splash->scale = 1;

	return splash;
}

int splash_destroy(splash_t* splash)
{
	free(splash);
	term_destroy_splash_term();
	return 0;
}

int splash_set_clear(splash_t* splash, uint32_t clear_color)
{
	splash->clear = clear_color;
	return 0;
}

int splash_add_image(splash_t* splash, char* filespec)
{
	image_t* image;
	int32_t offset_x, offset_y;
	char* filename;
	uint32_t duration;
	if (splash->num_images >= MAX_SPLASH_IMAGES)
		return 1;

	filename = (char*)malloc(strlen(filespec) + 1);
	parse_filespec(filespec,
			filename,
			&offset_x, &offset_y, &duration,
			splash->default_duration,
			splash->offset_x,
			splash->offset_y);

	image = image_create();
	image_set_filename(image, filename);
	image_set_offset(image, offset_x, offset_y);
	if (splash->scale == 0)
		image_set_scale(image, splash_is_hires(splash) ? 2 : 1);
	else
		image_set_scale(image, splash->scale);
	splash->image_frames[splash->num_images].image = image;
	splash->image_frames[splash->num_images].duration = duration;
	splash->num_images++;

	free(filename);
	return 0;
}

int splash_run(splash_t* splash)
{
	int i;
	int status = 0;
	/*
	 * Counters for throttling error messages. Only at most MAX_SPLASH_IMAGES
	 * of each type of error are logged so every frame of animation could log
	 * error message but it wouldn't spam the log.
	 */
	int ec_li = 0, ec_ts = 0, ec_ip = 0;
	int64_t last_show_ms;
	int64_t now_ms;
	int64_t sleep_ms;
	struct timespec sleep_spec;
	image_t* image;
	uint32_t duration;
	int32_t c, loop_start, loop_count;
	bool active = false;

	terminal_t *terminal = term_get_terminal(TERM_SPLASH_TERMINAL);
	if (!terminal)
		return -ENOENT;

	/* Update the bootstat metrics once the first image is shown */
	errno = 0;
	status = system("/usr/sbin/bootstat splash-screen-visible");
	if (status) {
		LOG(ERROR, "Failed to execute 'bootstat splash-screen-visible': "
			"status = %d, errno = %d (%s)",
			status, errno, strerror(errno));
	}

	/*
	 * First draw the actual splash screen
	 */
	term_set_background(terminal, splash->clear);
	term_clear(terminal);
	term_set_current_to(terminal);
	term_update_current_link();

	last_show_ms = -1;
	loop_count = (splash->loop_start >= 0 && splash->loop_start < splash->num_images) ? splash->loop_count : 1;
	loop_start = (splash->loop_start >= 0 && splash->loop_start < splash->num_images) ? splash->loop_start : 0;

	for (c = 0; ((loop_count < 0) ? true : (c < loop_count)); c++)
	for (i = (c > 0) ? loop_start : 0; i < splash->num_images; i++) {
		image = splash->image_frames[i].image;
		status = image_load_image_from_file(image);
		if (status != 0 && ec_li < MAX_SPLASH_IMAGES) {
			LOG(WARNING, "image_load_image_from_file %s failed: %d:%s.",
				image_get_filename(image), status, strerror(status));
			ec_li++;
		}
		/*
		 * Check status again after timing code so we preserve animation
		 * frame timings and dont's monopolize CPU time.
		 */
		now_ms = get_monotonic_time_ms();
		if (last_show_ms > 0) {
			if (splash->loop_start >= 0 && i >= splash->loop_start)
				duration = splash->loop_duration;
			else
				duration = splash->image_frames[i].duration;
			sleep_ms = duration - (now_ms - last_show_ms);
			if (sleep_ms > 0) {
				sleep_spec.tv_sec = sleep_ms / MS_PER_SEC;
				sleep_spec.tv_nsec = (sleep_ms % MS_PER_SEC) * NS_PER_MS;
				nanosleep(&sleep_spec, NULL);
			}
		}

		now_ms = get_monotonic_time_ms();
		if (status != 0) {
			goto img_error;
		}

		if (i >= splash->loop_start) {
			image_set_offset(image,
					splash->loop_offset_x,
					splash->loop_offset_y);
		}

		status = term_show_image(terminal, image);
		if (status != 0 && ec_ts < MAX_SPLASH_IMAGES) {
			LOG(WARNING, "term_show_image failed: %d:%s.", status, strerror(status));
			ec_ts++;
			goto img_error;
		}

		if (!active) {
			/*
			 * Set video mode on first frame so user does not see
			 * us drawing first frame.
			 */
			term_activate(terminal);
			active = true;
		}

		status = main_process_events(1);
		if (status != 0 && ec_ip < MAX_SPLASH_IMAGES) {
			LOG(WARNING, "input_process failed: %d:%s.", status, strerror(status));
			ec_ip++;
		}
img_error:
		last_show_ms = now_ms;

		image_release(image);
		/* see if we can initialize DBUS */
		if (!dbus_is_initialized())
			dbus_init();
		if (status != 0) {
			break;
		}
	}

	for (i = 0; i < splash->num_images; i++) {
		image_destroy(splash->image_frames[i].image);
	}

	return status;
}

void splash_set_offset(splash_t* splash, int32_t x, int32_t y)
{
	if (splash) {
		splash->offset_x = x;
		splash->offset_y = y;
	}
}

int splash_num_images(splash_t* splash)
{
	if (splash)
		return splash->num_images;

	return 0;
}

void splash_set_loop_count(splash_t* splash, int32_t count)
{
	if (splash)
		splash->loop_count = count;
}

void splash_set_default_duration(splash_t* splash, uint32_t duration)
{
	if (splash)
		splash->default_duration = duration;
}

void splash_set_loop_start(splash_t* splash, int32_t loop_start)
{
	if (splash)
		splash->loop_start = loop_start;
}

void splash_set_loop_duration(splash_t* splash, uint32_t duration)
{
	if (splash)
		splash->loop_duration = duration;
}

void splash_set_loop_offset(splash_t* splash, int32_t x, int32_t y)
{
	if (splash) {
		splash->loop_offset_x = x;
		splash->loop_offset_y = y;
	}
}

void splash_set_scale(splash_t* splash, uint32_t scale)
{
	if (scale > MAX_SCALE_FACTOR)
		scale = MAX_SCALE_FACTOR;
	if (splash)
		splash->scale = scale;
}

int splash_is_hires(splash_t* splash)
{
	terminal_t *terminal = term_get_terminal(TERM_SPLASH_TERMINAL);
	if (!terminal)
		return 0;

	if (term_getfb(terminal))
		return image_is_hires(term_getfb(terminal));
	return 0;
}

void splash_redrm(splash_t* splash)
{
	terminal_t *terminal = term_get_terminal(TERM_SPLASH_TERMINAL);
	if (!terminal)
		return;
	term_redrm(terminal);
}
