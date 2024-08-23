# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

FRECON_LITE ?= 0

PC_DEPS = libdrm libpng libtsm
ifeq ($(FRECON_LITE),1)
FRECON_OBJECTS = $(filter-out %_full.o,$(C_OBJECTS))
CPPFLAGS += -DFRECON_LITE=1
TARGET ?= frecon-lite
else
FRECON_OBJECTS = $(filter-out %_lite.o,$(C_OBJECTS))
PC_DEPS += dbus-1 libudev
CPPFLAGS += -DFRECON_LITE=0
TARGET ?= frecon
endif

PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))

CPPFLAGS += -std=c99 -D_GNU_SOURCE=1
CFLAGS += -Wall -Wsign-compare -Wpointer-arith -Wcast-qual -Wcast-align

CPPFLAGS += $(PC_CFLAGS) -I$(OUT)
LDLIBS += $(PC_LIBS)

$(OUT)glyphs.h: $(SRC)/font_to_c.py $(SRC)/ter-u16n.bdf
	$(SRC)/font_to_c $(SRC)/ter-u16n.bdf $(OUT)glyphs.h

font.o.depends: $(OUT)glyphs.h

CC_BINARY($(TARGET)): $(FRECON_OBJECTS)

all: CC_BINARY($(TARGET))

clean: CLEAN($(TARGET))

install: all
	mkdir -p $(DESTDIR)/sbin
	install -m 755 $(OUT)/$(TARGET) $(DESTDIR)/sbin
