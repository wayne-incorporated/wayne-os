/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdlib.h>
#include <stdbool.h>

bool dbus_init()
{
	return true;
}

void dbus_destroy(void)
{
}

void dbus_add_fds(fd_set* read_set, fd_set* exception_set, int *maxfd)
{
}

void dbus_dispatch_io(void)
{
}

void dbus_report_user_activity(int activity_type)
{
}

bool dbus_take_display_ownership(void)
{
	return true;
}

bool dbus_release_display_ownership(void)
{
	return true;
}

bool dbus_is_initialized(void)
{
	return true;
}

void dbus_set_login_prompt_visible_callback(void (*callback)(void))
{
}

void dbus_set_suspend_done_callback(void (*callback)(void*),
				    void* userptr)
{
}
