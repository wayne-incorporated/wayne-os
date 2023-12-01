/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdarg.h>
#include <stdio.h>

#include "crosid.h"

static enum log_level current_log_level;

void crosid_set_log_level(enum log_level log_level)
{
	current_log_level = log_level;
}

void crosid_log(enum log_level log_level, const char *restrict format, ...)
{
	va_list args;

	if (log_level > current_log_level)
		return;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}
