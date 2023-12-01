# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include common.mk

# Build a statically linked PIC library
CC_STATIC_LIBRARY(component/subcomponent/libsubcomponent.pic.a): \
  $(component_subcomponent_C_OBJECTS)
CC_STATIC_LIBRARY(component/subcomponent/libsubcomponent.pie.a): \
  $(component_subcomponent_C_OBJECTS)
clean: CLEAN(component/subcomponent/libsubcomponent.*.a)
CC_LIBRARY(component/subcomponent/libsubcomponent.so): \
  $(component_subcomponent_C_OBJECTS)
clean: CLEAN(component/subcomponent/libsubcomponent.so)
