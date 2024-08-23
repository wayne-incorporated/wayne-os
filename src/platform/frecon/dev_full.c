/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <libudev.h>
#include <string.h>

#include "dev.h"
#include "input.h"
#include "term.h"
#include "util.h"

static struct udev* udev = NULL;
static struct udev_monitor* udev_monitor = NULL;
static int udev_fd = -1;

static bool dev_is_keyboard_device(struct udev_device* dev)
{
	const char *keyboard = udev_device_get_property_value(dev, "ID_INPUT_KEYBOARD");

	if (keyboard && !strcmp(keyboard, "1"))
		return true;

	return false;
}

static void dev_add_existing_input_devs(void)
{
	struct udev_enumerate* udev_enum;
	struct udev_list_entry* devices, *deventry;
	udev_enum = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(udev_enum, "input");
	udev_enumerate_scan_devices(udev_enum);
	devices = udev_enumerate_get_list_entry(udev_enum);
	udev_list_entry_foreach(deventry, devices) {
		const char* syspath;
		struct udev_device* dev;
		syspath = udev_list_entry_get_name(deventry);
		dev = udev_device_new_from_syspath(udev, syspath);
		if (dev_is_keyboard_device(dev))
			input_add(udev_device_get_devnode(dev));
		udev_device_unref(dev);
	}
	udev_enumerate_unref(udev_enum);
}

int dev_init(void)
{
	udev = udev_new();
	if (!udev)
		return -ENOENT;

	udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
	if (!udev_monitor) {
		udev_unref(udev);
		udev = NULL;
		return -ENOENT;
	}
	udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "input",
							NULL);
	udev_monitor_filter_add_match_subsystem_devtype(udev_monitor, "drm",
							"drm_minor");
	udev_monitor_enable_receiving(udev_monitor);
	udev_fd = udev_monitor_get_fd(udev_monitor);

	dev_add_existing_input_devs();

	return 0;
}

void dev_close(void)
{
	if (!udev_monitor) {
		return;
	}
	udev_monitor_unref(udev_monitor);
	udev_monitor = NULL;
	udev_unref(udev);
	udev = NULL;
	udev_fd = -1;
}

void dev_add_fds(fd_set* read_set, fd_set* exception_set, int *maxfd)
{
	FD_SET(udev_fd, read_set);
	FD_SET(udev_fd, exception_set);
	if (udev_fd > *maxfd)
		*maxfd = udev_fd;
}

void dev_dispatch_io(fd_set* read_set, fd_set* exception_set)
{
	if (FD_ISSET(udev_fd, exception_set)) {
		/* udev died on us? */
		LOG(ERROR, "Exception on udev fd");
		return;
	}

	if (FD_ISSET(udev_fd, read_set)
	    && !FD_ISSET(udev_fd, exception_set)) {
		/* we got an udev notification */
		struct udev_device* dev =
		    udev_monitor_receive_device(udev_monitor);
		if (dev) {
			if (!strcmp("input", udev_device_get_subsystem(dev))) {
				if (!strcmp("add", udev_device_get_action(dev))) {
					if (dev_is_keyboard_device(dev))
						input_add(udev_device_get_devnode(dev));
				} else if (!strcmp("remove", udev_device_get_action(dev))) {
					input_remove(udev_device_get_devnode(dev));
				}
			} else if (!strcmp("drm", udev_device_get_subsystem(dev))
					&& !strcmp("drm_minor", udev_device_get_devtype(dev))
					&& !strcmp("change", udev_device_get_action(dev))) {
				const char *hotplug = udev_device_get_property_value(dev, "HOTPLUG");
				if (hotplug && atoi(hotplug) == 1)
					term_monitor_hotplug();
			}
			udev_device_unref(dev);
		}
	}
}
