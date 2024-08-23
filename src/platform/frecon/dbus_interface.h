/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef DBUS_INTERFACE_H_
#define DBUS_INTERFACE_H_

/* Minimal set of power manager constants copied from
   platform/system_api/dbus/service_constants.h which are C++
   header file so we can't use it in our code directly */

static const char kPowerManagerInterface[] = "org.chromium.PowerManager";
static const char kPowerManagerServicePath[] = "/org/chromium/PowerManager";
static const char kPowerManagerServiceName[] = "org.chromium.PowerManager";
/* Methods exposed by powerd. */
static const char kDecreaseScreenBrightnessMethod[] = "DecreaseScreenBrightness";
static const char kIncreaseScreenBrightnessMethod[] = "IncreaseScreenBrightness";
static const char kHandleUserActivityMethod[] = "HandleUserActivity";
/* Values */
static const int kBrightnessTransitionGradual = 1;
static const int kBrightnessTransitionInstant = 2;
enum UserActivityType {
	USER_ACTIVITY_OTHER = 0,
	USER_ACTIVITY_BRIGHTNESS_UP_KEY_PRESS = 1,
	USER_ACTIVITY_BRIGHTNESS_DOWN_KEY_PRESS = 2,
	USER_ACTIVITY_VOLUME_UP_KEY_PRESS = 3,
	USER_ACTIVITY_VOLUME_DOWN_KEY_PRESS = 4,
	USER_ACTIVITY_VOLUME_MUTE_KEY_PRESS = 5,
};

static const char kSuspendDoneSignal[] = "SuspendDone";
static const char kSuspendDoneRule[] = "interface='org.chromium.PowerManager',type='signal'";

static const char kSessionManagerInterface[] = "org.chromium.SessionManagerInterface";
static const char kSessionManagerServicePath[] = "/org/chromium/SessionManager";
static const char kSessionManagerServiceName[] = "org.chromium.SessionManager";

static const char kLoginPromptVisibleSignal[] = "LoginPromptVisible";
static const char kLoginPromptVisibleRule[] = "interface='org.chromium.SessionManagerInterface',type='signal'";

static const char kDisplayServiceName[] = "org.chromium.DisplayService";
static const char kDisplayServicePath[] = "/org/chromium/DisplayService";
static const char kDisplayServiceInterface[] =
  "org.chromium.DisplayServiceInterface";
static const char kTakeOwnership[] = "TakeOwnership";
static const char kReleaseOwnership[] = "ReleaseOwnership";

static const char kFreconDbusInterface[] = "org.chromium.frecon";
static const char kFreconDbusPath[] = "/org/chromium/frecon";

#endif // FRECON_DBUS_API_H_
