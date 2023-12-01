# Copyright 2015 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

CPPFLAGS += -Ilinux/include/linux -Iuserspace

PREFIX ?= /usr
INCLUDEDIR ?= $(PREFIX)/include
GENTOO_LIBDIR ?= lib
LIBDIR ?= $(PREFIX)/$(GENTOO_LIBDIR)

# See the README file for the list of files required to embed this library in
# userspace code.
xz_embedded_src_files := \
  linux/lib/xz/xz_crc32.c \
  linux/lib/xz/xz_dec_bcj.c \
  linux/lib/xz/xz_dec_lzma2.c \
  linux/lib/xz/xz_dec_stream.c

xz_embedded_private_headers := \
  linux/lib/xz/xz_lzma2.h \
  linux/lib/xz/xz_private.h \
  linux/lib/xz/xz_stream.h \
  userspace/xz_config.h

xz_embedded_install_headers := \
  linux/include/linux/xz.h

xz_embedded_obj_files := $(xz_embedded_src_files:.c=.o)
xz_embedded_lib := libxz-embedded.a
xz_embedded_pc := xz-embedded.pc

.PHONY: all clean install

all: $(xz_embedded_lib) $(xz_embedded_pc)

$(xz_embedded_obj_files): CFLAGS += -fPIC
$(xz_embedded_obj_files): $(xz_embedded_private_headers) $(xz_embedded_install_headers)

$(xz_embedded_lib): $(xz_embedded_obj_files)
	$(AR) rcs $@ $^

$(xz_embedded_pc): $(xz_embedded_pc).in
	sed "s,%PREFIX%,${PREFIX},;s,%INCLUDEDIR%,${INCLUDEDIR},;s,%LIBDIR%,${LIBDIR}," $< >$@

clean:
	rm -rf $(xz_embedded_obj_files) $(xz_embedded_lib) $(xz_embedded_pc)

install: all
	install -d $(DESTDIR)/$(LIBDIR) $(DESTDIR)/$(LIBDIR)/pkgconfig $(DESTDIR)/$(INCLUDEDIR)/xz-embedded
	install $(xz_embedded_lib) $(DESTDIR)/$(LIBDIR)
	install --mode=644 $(xz_embedded_pc) $(DESTDIR)/$(LIBDIR)/pkgconfig
	install --mode=644 $(xz_embedded_install_headers) $(DESTDIR)/$(INCLUDEDIR)/xz-embedded
