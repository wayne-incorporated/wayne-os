# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

CPPFLAGS += -I$(OUT)/include -DHAVE_JPEG

LOCAL_OBJS := \
	source/compare.o           \
	source/compare_common.o    \
	source/compare_neon.o      \
	source/compare_neon64.o    \
	source/compare_gcc.o       \
	source/convert.o           \
	source/convert_argb.o      \
	source/convert_from.o      \
	source/convert_from_argb.o \
	source/convert_jpeg.o      \
	source/convert_to_argb.o   \
	source/convert_to_i420.o   \
	source/cpu_id.o            \
	source/mjpeg_decoder.o     \
	source/mjpeg_validate.o    \
	source/planar_functions.o  \
	source/rotate.o            \
	source/rotate_any.o        \
	source/rotate_argb.o       \
	source/rotate_common.o     \
	source/rotate_neon.o       \
	source/rotate_neon64.o     \
	source/rotate_gcc.o        \
	source/row_any.o           \
	source/row_common.o        \
	source/row_neon.o          \
	source/row_neon64.o        \
	source/row_gcc.o           \
	source/scale.o             \
	source/scale_any.o         \
	source/scale_argb.o        \
	source/scale_common.o      \
	source/scale_neon.o        \
	source/scale_neon64.o      \
	source/scale_gcc.o         \
	source/scale_uv.o          \
	source/video_common.o

$(eval $(call add_object_rules,$(LOCAL_OBJS),CXX,cc,CXXFLAGS))

LDLIBS += -ljpeg

CXX_STATIC_LIBRARY(libyuv.pic.a): $(CXX_OBJECTS) $(LOCAL_OBJS)

all: CXX_STATIC_LIBRARY(libyuv.pic.a)

clean: CLEAN(libyuv.pic.a)
