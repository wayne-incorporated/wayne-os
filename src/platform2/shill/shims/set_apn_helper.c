// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#define CONNMAN_SERVICE "org.chromium.flimflam"

#define CONNMAN_SERVICE_INTERFACE CONNMAN_SERVICE ".Service"

static void append(DBusMessageIter* dict, const char* key, const char* value) {
  DBusMessageIter entry;

  dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

  dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &value);

  dbus_message_iter_close_container(dict, &entry);
}

int main(int argc, char* argv[]) {
  DBusConnection* conn;
  DBusError error;
  DBusMessage* msg;
  DBusMessageIter iter, value, dict;
  const char* property;
  char* args;
  char* cp;
  char* argname;
  char* argvalue;
  int done;

  if (argc < 4) {
    fprintf(stderr,
            "Usage: %s <service-dbus-path> <property-name> <apn-args>\n",
            argv[0]);
    return 1;
  }

  dbus_error_init(&error);

  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  if (conn == NULL) {
    if (dbus_error_is_set(&error) == TRUE) {
      fprintf(stderr, "%s\n", error.message);
      dbus_error_free(&error);
    } else
      fprintf(stderr, "Failed to get on system bus\n");
    return 1;
  }

  msg = dbus_message_new_method_call(CONNMAN_SERVICE, argv[1],
                                     CONNMAN_SERVICE_INTERFACE, "SetProperty");
  if (msg == NULL) {
    dbus_connection_unref(conn);
    fprintf(stderr, "Failed to allocate method call\n");
    return 1;
  }

  dbus_message_set_no_reply(msg, TRUE);

  dbus_message_iter_init_append(msg, &iter);

  property = argv[2];
  dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

  dbus_message_iter_open_container(
      &iter, DBUS_TYPE_VARIANT,
      DBUS_TYPE_ARRAY_AS_STRING DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
          DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
              DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
      &value);

  dbus_message_iter_open_container(
      &value, DBUS_TYPE_ARRAY,
      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING DBUS_TYPE_STRING_AS_STRING
          DBUS_TYPE_STRING_AS_STRING DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
      &dict);

  args = argv[3];
  cp = args;
  done = 0;

  while (!done) {
    argname = cp;
    cp = strchr(cp, ',');
    if (cp == NULL) {
      fprintf(stderr, "Badly formed argument string\n");
      dbus_message_unref(msg);
      dbus_connection_unref(conn);
      return 1;
    }
    *cp++ = '\0';
    argvalue = cp;
    cp = strchr(cp, ',');
    if (cp == NULL)
      done = 1;
    else
      *cp++ = '\0';
    append(&dict, argname, argvalue);
  }

  dbus_message_iter_close_container(&iter, &dict);
  dbus_message_iter_close_container(&dict, &value);

  dbus_connection_send(conn, msg, NULL);

  dbus_message_unref(msg);
  dbus_connection_unref(conn);

  return 0;
}
