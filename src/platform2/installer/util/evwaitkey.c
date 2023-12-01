// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#define _GNU_SOURCE

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/input.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static const char kDevInputEvent[] = "/dev/input";
static const char kEventDevName[] = "event";

// Maximum number of event devices to monitor. 10 should be large enough for
// normal use case. This uses a #define rather than a variable so that it can
// be used as an array size.
#define MAX_FDS 10

// Determines if the given |bit| is set in the |bitmask| array.
static bool TestBit(const int bit, const uint8_t* bitmask) {
  return (bitmask[bit / 8] >> (bit % 8)) & 1;
}

static int IsEventDevice(const struct dirent* dir) {
  return strncmp(kEventDevName, dir->d_name, strlen(kEventDevName)) == 0;
}

static bool IsUSBDevice(const int fd) {
  struct input_id id;
  if (ioctl(fd, EVIOCGID, &id) == -1) {
    err(EXIT_FAILURE, "Failed to ioctl to determine device bus");
  }

  return id.bustype == BUS_USB;
}

static bool IsKeyboardDevice(const int fd) {
  uint8_t evtype_bitmask[EV_MAX / 8 + 1];
  if (ioctl(fd, EVIOCGBIT(0, sizeof(evtype_bitmask)), evtype_bitmask) == -1) {
    err(EXIT_FAILURE, "Failed to ioctl to determine supported event types");
  }

  // The device is a "keyboard" if it supports EV_KEY events. Though, it is not
  // necessarily a real keyboard; EV_KEY events could also be e.g. volume
  // up/down buttons on a device.
  return TestBit(EV_KEY, evtype_bitmask);
}

static bool SupportsAllKeys(const int fd,
                            const int* events,
                            const int num_events) {
  uint8_t key_bitmask[KEY_MAX / 8 + 1];
  if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bitmask)), key_bitmask) == -1) {
    err(EXIT_FAILURE, "Failed to ioctl to determine supported key events");
  }

  for (int i = 0; i < num_events; ++i) {
    if (!TestBit(events[i], key_bitmask)) {
      return false;
    }
  }

  return true;
}

static int WaitForKeys(const int* fds,
                       const int num_fds,
                       const int* events,
                       const int num_events) {
  // Boolean array to keep track of whether a key is currently up or down.
  bool key_states[MAX_FDS][KEY_MAX + 1] = {{}};

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    err(EXIT_FAILURE, "epoll_create failed");
  }

  for (int i = 0; i < num_fds; ++i) {
    struct epoll_event ep_event;
    ep_event.data.u32 = i;
    ep_event.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &ep_event) < 0) {
      err(EXIT_FAILURE, "epoll_ctl failed");
    }
  }

  while (true) {
    struct epoll_event ep_event;
    if (epoll_wait(epfd, &ep_event, 1, -1) <= 0) {
      err(EXIT_FAILURE, "epoll_wait failed");
    }

    struct input_event ev;
    int index = ep_event.data.u32;
    int rd = read(fds[index], &ev, sizeof(ev));
    if (rd != sizeof(ev)) {
      err(EXIT_FAILURE, "Could not read event");
    }

    // A keyboard device may generate events other than EV_KEY, so we should
    // explicitly check here. Also explicitly check |ev.code| is in range, just
    // in case.
    if (ev.type == EV_KEY && ev.code <= KEY_MAX) {
      for (int i = 0; i < num_events; ++i) {
        if (events[i] == ev.code) {
          // We need to perform a bit of extra logic to handle buttons that may
          // have already been pressed when we entered recovery. For example,
          // if a user is holding down their volume keys as they enter recovery,
          // then the key repeat event will get fed into here, and we don't want
          // to act on it since it does not constitute acknowledgment.
          //
          // So, we force that we must have seen the key be pressed and then
          // released in the time that we have been in recovery.
          if (ev.value == 0 && key_states[index][ev.code]) {
            close(epfd);
            // Key was released while we knew it was pressed; we're done.
            return ev.code;
          } else if (ev.value == 1) {
            // Only count first presses, long holds/key repeats from entering
            // recovery will have |ev.value| == 2, so won't go down here.
            key_states[index][ev.code] = true;
          }
        }
      }
    }
  }

  // Not reached.
}

static void ShowHelpAndExit(FILE* out) {
  fprintf(out,
          "evwaitkey\n"
          "\n"
          "This utility allows waiting on arbitrary key inputs to a device's\n"
          "primary keyboard. It's primarily intended for use from\n"
          "non-interactive scripts that must obtain user input, e.g.\n"
          "physical presence checks in the recovery installer.\n"
          "\n"
          "It takes at least one key code (as determined by evtest) as input\n"
          "and prints the first key in the given list that was pressed by the\n"
          "user. It may block indefinitely if no key was pressed.\n"
          "\n"
          "Example usage (waiting either for escape key code 1 or enter key "
          "code 28):\n"
          "\n"
          "    $ evwaitkey --keys 1:28\n"
          "    <user presses enter>\n"
          "    28\n"
          "\n"
          "Example usage in script:\n"
          "\n"
          "    KEY_ESC=1\n"
          "    KEY_ENTER=28\n"
          "\n"
          "    if [ $(evwaitkey --keys $KEY_ESC:$KEY_ENTER) = $KEY_ESC ]; "
          "then\n"
          "      echo \"Escape pressed\"\n"
          "    else\n"
          "      echo \"Enter pressed\"\n"
          "    fi\n"
          "\n\n"
          "--help (Shows this help message)\n"
          "--check (Checks if the requested keys are available, exits with an\n"
          "         error if they are not)\n"
          "--include_usb (Whether USB devices should be scanned for inputs)\n"
          "--keys (Colon-separated list of keycodes to listen for)\n\n");
  exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
  static int flag_include_usb = 0;
  static int flag_check = 0;
  static int flag_help = 0;
  static const struct option long_options[] = {
      {"check", no_argument, &flag_check, 1},
      {"include_usb", no_argument, &flag_include_usb, 1},
      {"help", no_argument, &flag_help, 1},
      {"keys", required_argument, NULL, 'k'},
  };

  int events[KEY_MAX + 1];
  int num_events = 0;

  int opt;
  int opt_idx = 0;
  while ((opt = getopt_long(argc, argv, "", long_options, &opt_idx)) != -1) {
    switch (opt) {
      case 'k': {
        char* token = strtok(optarg, ":");
        while (token != NULL && num_events < KEY_MAX) {
          char* end;
          int event = strtol(token, &end, 10);
          if (end == token || *end != '\0' || event < 0 || event > KEY_MAX) {
            errx(EXIT_FAILURE, "'%s' is not a valid keycode.", token);
          }

          events[num_events++] = event;
          token = strtok(NULL, ":");
        }
        break;
      }
      case '?':
        return EXIT_FAILURE;
    }
  }

  if (flag_help || opt_idx == 0) {
    ShowHelpAndExit(flag_help ? stdout : stderr);
  }

  struct dirent** input_devs;
  int ndev = scandir(kDevInputEvent, &input_devs, IsEventDevice, NULL);
  int fds[MAX_FDS], num_fds = 0;

  for (int i = 0; i < ndev; ++i) {
    char* ev_dev;
    if (asprintf(&ev_dev, "%s/%s", kDevInputEvent, input_devs[i]->d_name) ==
        -1) {
      err(EXIT_FAILURE, "asprintf failed");
    }

    int fd = open(ev_dev, O_RDONLY | O_CLOEXEC);
    free(ev_dev);
    if (fd <= 0) {
      err(EXIT_FAILURE, "Failed to open event device");
    }

    // Listen on the first device that matches the event list.
    //
    // In the case of recovery, we should be ignoring input events from external
    // keyboards, since USB-attached devices can be tampered with by a remote
    // attacker to masquerade as keyboards and bypass physical presence checks.
    if ((flag_include_usb || !IsUSBDevice(fd)) && IsKeyboardDevice(fd) &&
        SupportsAllKeys(fd, events, num_events)) {
      fds[num_fds++] = fd;
      if (flag_check || num_fds >= MAX_FDS) {
        break;
      }
    } else {
      close(fd);
    }
  }

  if (num_fds > 0) {
    if (!flag_check) {
      int ev = WaitForKeys(fds, num_fds, events, num_events);
      printf("%d\n", ev);
    }

    for (int i = 0; i < num_fds; i++) {
      close(fds[i]);
    }

    return EXIT_SUCCESS;
  }

  if (!flag_check) {
    warnx("Could not find device supporting requested keys.");
  }

  return EXIT_FAILURE;
}
