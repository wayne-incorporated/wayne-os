# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PWD ?= $(CURDIR)
OUT ?= $(PWD)/build-opt-local

include common.mk

PC_DEPS = libchrome libbrillo openssl
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))

CXXFLAGS += -I$(SRC)/.. $(PC_CFLAGS)
LDLIBS += $(PC_LIBS)

TEST_OBJS := $(filter %_test.o trunks_testrunner.o mock_%.o, $(CXX_OBJECTS))
SHARED_OBJS := $(filter-out $(TEST_OBJS), $(CXX_OBJECTS))

CXX_BINARY(trunks_testrunner): CXXFLAGS += $(shell gtest-config --cxxflags) \
                                           $(shell gmock-config --cxxflags)
CXX_BINARY(trunks_testrunner): LDLIBS += $(shell gtest-config --libs) \
                                         $(shell gmock-config --libs)
CXX_BINARY(trunks_testrunner): $(TEST_OBJS) $(SHARED_OBJS)

all: $(SHARED_OBJS)
tests: TEST(CXX_BINARY(trunks_testrunner))
clean: CLEAN(CXX_BINARY(trunks_testrunner))
