# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CFLAGS += -Wall -Wextra -Werror -g
CFLAGS += -Wno-unused-parameter  # set_do_exit(), reg_handler(), wait_handler()
CFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

PKG_CONFIG ?= pkg-config
PC_DEPS = libnl-genl-3.0 libnl-3.0
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))

CFLAGS += $(PC_CFLAGS)
LDLIBS += $(PC_LIBS)

%.o: %.c regdb.h reglib.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

all: testbed_regulatory send_management_frame

testbed_regulatory: testbed_regulatory.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

send_management_frame: send_management_frame.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lpcap
