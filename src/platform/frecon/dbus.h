/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef FRECON_DBUS_H
#define FRECON_DBUS_H

#include <sys/select.h>
#include <stdbool.h>
#include <memory.h>
#include <stdio.h>

bool dbus_init();
void dbus_destroy(void);
void dbus_add_fds(fd_set* read_set, fd_set* exception_set, int *maxfd);
void dbus_dispatch_io(void);
void dbus_report_user_activity(int activity_type);
bool dbus_take_display_ownership(void);
bool dbus_release_display_ownership(void);
bool dbus_is_initialized(void);
void dbus_set_login_prompt_visible_callback(void (*callback)(void));
void dbus_set_suspend_done_callback(void (*callback)(void*),
				    void* userptr);

#endif // FRECON_DBUS_H
