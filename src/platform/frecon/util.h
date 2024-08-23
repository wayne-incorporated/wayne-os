/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))

#define ARRAY_SIZE(A) (sizeof(A)/sizeof(*(A)))

#define  MS_PER_SEC             (1000LL)
#define  NS_PER_SEC             (1000LL * 1000LL * 1000LL)
#define  NS_PER_MS              (NS_PER_SEC / MS_PER_SEC);

/* Returns the current CLOCK_MONOTONIC time in milliseconds. */
static inline int64_t get_monotonic_time_ms() {
	struct timespec spec;
	clock_gettime(CLOCK_MONOTONIC, &spec);
	return MS_PER_SEC * spec.tv_sec + spec.tv_nsec / NS_PER_MS;
}

#define ERROR                 (LOG_ERR)
#define WARNING               (LOG_WARNING)
#define INFO                  (LOG_INFO)
#define DEBUG                 (LOG_DEBUG)

/* Don't print debug messages by default. */
#ifndef LOG_LEVEL
#define LOG_LEVEL             (LOG_DEBUG-1)
#endif

#define LOG(severity, fmt, ...) do { \
		if (severity <= LOG_LEVEL) \
			fprintf(stderr, "<%i>frecon[%d]: " fmt "\n", \
				severity, getpid(), ##__VA_ARGS__); \
	} while (0)

void daemonize(bool wait_child);
void daemon_exit_code(char code);
void parse_location(char* loc_str, int* x, int* y);
void parse_filespec(char* filespec, char* filename,
		int32_t* offset_x, int32_t* offset_y, uint32_t* duration,
		uint32_t default_duration, int32_t default_x, int32_t default_y);
void parse_image_option(char* optionstr, char** name, char** val);

/* make sure stdio file descriptors are somewhat sane */
void fix_stdio(void);
bool write_string_to_file(const char *path, const char *s);

#endif
