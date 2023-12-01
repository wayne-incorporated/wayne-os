# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

PC_DEPS =

ifeq ($(USE_VAAPI),yes)
  CPPFLAGS += -DUSE_VAAPI
  PC_DEPS += libva-drm
  VAAPI_OBJS = $(filter util_vaapi.o,$(C_OBJECTS))
endif

ifeq ($(USE_V4L2_CODEC),yes)
  CPPFLAGS += -DUSE_V4L2_CODEC
  V4L2_OBJS = $(filter util_v4l2.o,$(C_OBJECTS))
endif

ifneq ($(PC_DEPS),)
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))
endif

CPPFLAGS += $(PC_CFLAGS)
LDLIBS += $(PC_LIBS)

CC_BINARY(avtest_label_detect): \
  $(filter-out util_vaapi.o util_v4l2.o,$(C_OBJECTS)) \
  $(VAAPI_OBJS) $(V4L2_OBJS)

all: CC_BINARY(avtest_label_detect)
clean: CLEAN(CC_BINARY(avtest_label_detect))
