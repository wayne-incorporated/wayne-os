// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "brillo/syslog_logging.h"

constexpr char kBgColorFlag[] = "bgcolor";
constexpr char kWidthFlag[] = "width";
constexpr char kHeightFlag[] = "height";
constexpr char kTitleFlag[] = "title";

// Creates an X window the same size as the display and fills its background
// with a solid color that can be specified as the only parameter (in hex or
// base 10). Closes on any keypress.
int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog);
  LOG(INFO) << "Starting x11_demo application";

  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  uint32_t bgcolor = 0x99EE44;
  if (cl->HasSwitch(kBgColorFlag)) {
    bgcolor =
        strtoul(cl->GetSwitchValueASCII(kBgColorFlag).c_str(), nullptr, 0);
  }
  std::string title = "x11_demo";
  if (cl->HasSwitch(kTitleFlag)) {
    title = cl->GetSwitchValueASCII(kTitleFlag);
  }

  Display* dpy = XOpenDisplay(nullptr);
  if (!dpy) {
    LOG(ERROR) << "Failed opening display";
    return -1;
  }

  int screen = DefaultScreen(dpy);
  Window win;
  int x, y;
  unsigned int width, height, border, depth;
  if (XGetGeometry(dpy, RootWindow(dpy, screen), &win, &x, &y, &width, &height,
                   &border, &depth) == 0) {
    LOG(ERROR) << "Failed getting screen geometry";
    return -1;
  }
  if (cl->HasSwitch(kWidthFlag)) {
    if (!base::StringToUint(cl->GetSwitchValueASCII(kWidthFlag), &width)) {
      LOG(ERROR) << "Invalid width parameter passed";
      return -1;
    }
  }
  if (cl->HasSwitch(kHeightFlag)) {
    if (!base::StringToUint(cl->GetSwitchValueASCII(kHeightFlag), &height)) {
      LOG(ERROR) << "Invalid height parameter passed";
      return -1;
    }
  }
  win = XCreateSimpleWindow(dpy, RootWindow(dpy, screen), x, y, width, height,
                            0, 0 /* black */, bgcolor);

  XClassHint* wmclass_hint = XAllocClassHint();
  wmclass_hint->res_name = wmclass_hint->res_class = strdup(title.c_str());
  XSetClassHint(dpy, win, wmclass_hint);
  XSelectInput(dpy, win, KeyPressMask);
  XMapWindow(dpy, win);
  XStoreName(dpy, win, title.c_str());

  LOG(INFO) << "x11_demo application displaying, waiting for keypress";
  XEvent evt;
  for (;;) {
    XNextEvent(dpy, &evt);
    if (evt.type == KeyPress) {
      LOG(INFO) << "x11_demo application detected keypress";
      break;
    }
  }

  XCloseDisplay(dpy);
  LOG(INFO) << "x11_demo application exiting";
  return 0;
}
