# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CPPFLAGS += -I. -Iinclude -DANDROID \
  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS += -L.

PREFIX ?= /usr/
INCLUDEDIR ?= $(PREFIX)/include
GENTOO_LIBDIR ?= lib
LIBDIR ?= $(PREFIX)/$(GENTOO_LIBDIR)

libsync_src_files := \
  sync.c \
  strlcpy.c

libsync_obj_files := $(libsync_src_files:.c=.o)
$(libsync_obj_files): CFLAGS += -fPIC

all: libsync.so libsync.pc

libsync.so: $(libsync_obj_files)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,$@ -shared -o $@ $^ $(LDLIBS)

libsync.pc: libsync.pc.template
	sed -e "s|@LIB_DIR@|${LIBDIR}|" "libsync.pc.template" > "libsync.pc"

.PHONY: all clean install

clean:
	rm -rf *.o *.so *.pc

install: all
	install -d $(DESTDIR)/$(LIBDIR) $(DESTDIR)/$(LIBDIR)/pkgconfig $(DESTDIR)/$(INCLUDEDIR)/sync
	install libsync.so $(DESTDIR)/$(LIBDIR)
	install --mode=644 include/sync/sync.h $(DESTDIR)/$(INCLUDEDIR)/sync
	install --mode=644 libsync.pc $(DESTDIR)/$(LIBDIR)/pkgconfig