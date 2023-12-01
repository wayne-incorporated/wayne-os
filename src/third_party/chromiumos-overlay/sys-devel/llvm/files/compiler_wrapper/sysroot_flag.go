// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"path/filepath"
	"strings"
)

func processSysrootFlag(builder *commandBuilder) {
	fromUser := false
	userSysroot := ""
	for _, arg := range builder.args {
		if arg.fromUser && strings.HasPrefix(arg.value, "--sysroot=") {
			fromUser = true
			sysrootArg := strings.Split(arg.value, "=")
			if len(sysrootArg) == 2 {
				userSysroot = sysrootArg[1]
			}
			break
		}
	}
	sysroot, syrootPresent := builder.env.getenv("SYSROOT")
	if syrootPresent {
		builder.updateEnv("SYSROOT=")
	}
	if sysroot == "" {
		// Use the bundled sysroot by default.
		sysroot = filepath.Join(builder.rootPath, "usr", builder.target.target)
	}
	if !fromUser {
		builder.addPreUserArgs("--sysroot=" + sysroot)
	} else {
		sysroot = userSysroot
	}

	libdir := "-L" + sysroot + "/usr/lib"
	if strings.Contains(builder.target.target, "64") {
		libdir += "64"
	}
	builder.addPostUserArgs(libdir)
}
