/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "util.h"

static int daemon_pipe[2] = { -1, -1 };

static int openfd(char *path, int flags, int reqfd)
{
	int fd = open(path, flags);
	if (fd < 0)
		return -1;

	if (fd == reqfd)
		return reqfd;

	if (dup2(fd, reqfd) >= 0) {
		close(fd);
		return reqfd;
	}

	close(fd);
	return -1;
}

static int init_daemon_stdio(void)
{
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	if (openfd("/dev/null", O_RDONLY, STDIN_FILENO) < 0)
		return -1;

	if (openfd("/dev/kmsg", O_WRONLY, STDOUT_FILENO) < 0)
		return -1;

	if (openfd("/dev/kmsg", O_WRONLY, STDERR_FILENO) < 0)
		return -1;

	return 0;
}

void daemonize(bool wait_child)
{
	pid_t pid;

	if (wait_child)
		if (pipe(daemon_pipe) < 0)
			exit(EXIT_FAILURE);

	pid = fork();
	if (pid == -1)
		return;
	else if (pid != 0) {
		if (wait_child) {
			char code = EXIT_FAILURE;
			close(daemon_pipe[1]);
			if (read(daemon_pipe[0], &code, sizeof(code)) < 0) {
				int c;
				/* Child has died? */
				if (errno == EPIPE)
					if (waitpid(pid, &c, 0) >= 0)
						exit(c); /* Propagate child exit code. */
				/* Just report failure. */
				exit(EXIT_FAILURE);
			}
			exit(code);
		}
		exit(EXIT_SUCCESS);
	}

	if (wait_child)
		close(daemon_pipe[0]);
	if (setsid() == -1)
		return;

	init_daemon_stdio();
}

void daemon_exit_code(char code)
{
	if (write(daemon_pipe[1], &code, sizeof(code)) != sizeof(code)) {
		LOG(ERROR, "failed to report exit code back to daemon parent");
	}
	close(daemon_pipe[1]);
}

static int is_valid_fd(int fd)
{
    return fcntl(fd, F_GETFL) != -1 || errno != EBADF;
}

void fix_stdio(void)
{
	if (!is_valid_fd(STDIN_FILENO)
	    || !is_valid_fd(STDOUT_FILENO)
	    || !is_valid_fd(STDERR_FILENO))
		init_daemon_stdio();
}

void parse_location(char* loc_str, int* x, int* y)
{
	int count = 0;
	char* savedptr;
	char* str;
	int* results[] = {x, y};
	long tmp;

	for (char* token = str = loc_str; token != NULL; str = NULL) {
		if (count > 1)
			break;

		token = strtok_r(str, ",", &savedptr);
		if (token) {
			tmp = MIN(INT_MAX, strtol(token, NULL, 0));
			*(results[count++]) = (int)tmp;
		}
	}
}

void parse_filespec(char* filespec, char* filename,
		    int32_t* offset_x, int32_t* offset_y, uint32_t* duration,
		    uint32_t default_duration,
		    int32_t default_x, int32_t default_y)
{
	char* saved_ptr;
	char* token;

	// defaults
	*offset_x = default_x;
	*offset_y = default_y;
	*duration = default_duration;

	token = filespec;
	token = strtok_r(token, ":", &saved_ptr);
	if (token)
		strcpy(filename, token);

	token = strtok_r(NULL, ":", &saved_ptr);
	if (token) {
		*duration = strtoul(token, NULL, 0);
		token = strtok_r(NULL, ",", &saved_ptr);
		if (token) {
			token = strtok_r(token, ",", &saved_ptr);
			if (token) {
				*offset_x = strtol(token, NULL, 0);
				token = strtok_r(token, ",", &saved_ptr);
				if (token)
					*offset_y = strtol(token, NULL, 0);
			}
		}
	}
}

void parse_image_option(char* optionstr, char** name, char** val)
{
	char** result[2] = { name, val };
	int count = 0;
	char* str;
	char* savedptr;

	for (char* token = str = optionstr; token != NULL; str = NULL) {
		if (count > 1)
			break;

		token = strtok_r(str, ":", &savedptr);
		if (token) {
			*(result[count]) = malloc(strlen(token) + 1);
			strcpy(*(result[count]), token);
			count++;
		}
	}
}

bool write_string_to_file(const char *path, const char *s)
{
	int fd;
	size_t towrite;
	ssize_t written;

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
	if (!fd)
		return false;

	towrite = strlen(s);
	written = write(fd, s, towrite);
	close(fd);

	if (written != (ssize_t)towrite) {
		LOG(ERROR, "Failed to write string%s to %s", s, path);
		unlink(path);
		return false;
	}
	return true;
}
