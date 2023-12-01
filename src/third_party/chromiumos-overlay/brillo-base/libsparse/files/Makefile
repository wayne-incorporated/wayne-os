# Copyright 2015 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

CPPFLAGS += -I. -Iinclude -DANDROID \
  -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS += -L.

PREFIX ?= /usr/
BINDIR ?= $(PREFIX)/bin
INCLUDEDIR ?= $(PREFIX)/include
GENTOO_LIBDIR ?= lib
LIBDIR ?= $(PREFIX)/$(GENTOO_LIBDIR)

libsparse_src_files := \
  backed_block.c \
  output_file.c \
  sparse.c \
  sparse_crc32.c \
  sparse_err.c \
  sparse_read.c
libsparse_obj_files := $(libsparse_src_files:.c=.o)
$(libsparse_obj_files): CFLAGS += -fPIC

simg2img_src_files := \
  simg2img.c
simg2img_obj_files := $(simg2img_src_files:.c=.o)

img2simg_src_files := \
  img2simg.c
img2simg_obj_files := $(img2simg_src_files:.c=.o)

simg2simg_src_files := \
  simg2simg.c
simg2simg_obj_files := $(simg2simg_src_files:.c=.o)

executables := simg2img img2simg simg2simg

all: libsparse.so $(executables)

libsparse.so: LDLIBS += -lz
libsparse.so: $(libsparse_obj_files)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,$@ -shared -o $@ $^ $(LDLIBS)

$(executables): libsparse.so
simg2img: $(simg2img_obj_files)
img2simg: $(img2simg_obj_files)
simg2simg: $(simg2simg_obj_files)

.PHONY: all clean install

clean:
	rm -rf *.o *.so $(executables)

install: all
	install -d $(DESTDIR)/$(BINDIR) $(DESTDIR)/$(LIBDIR) $(DESTDIR)/$(INCLUDEDIR)/sparse
	install $(executables) $(DESTDIR)/$(BINDIR)
	install libsparse.so $(DESTDIR)/$(LIBDIR)
	install --mode=644 include/sparse/sparse.h $(DESTDIR)/$(INCLUDEDIR)/sparse
