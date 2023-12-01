// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type useIWYUMode int

const iwyuCrashSubstring = "PLEASE submit a bug report"

const (
	iwyuModeNone useIWYUMode = iota
	iwyuModeAll
	iwyuModeError
)

var srcFileSuffixes = []string{
	".c",
	".cc",
	".cpp",
	".C",
	".cxx",
	".c++",
}

func findWithIWYUFlag(args []builderArg) (string, []builderArg) {
	for i := range args {
		if args[i].value == "--with-iwyu" {
			args = append(args[:i], args[i+1:]...)
			return "1", args
		}
	}
	return "", args
}

func processIWYUFlags(builder *commandBuilder) (cSrcFile string, iwyuFlags []string, mode useIWYUMode) {
	builder.transformArgs(func(arg builderArg) string {
		const prefix = "-iwyu-flag="
		if !strings.HasPrefix(arg.value, prefix) {
			return arg.value
		}

		iwyuFlags = append(iwyuFlags, arg.value[len(prefix):])
		return ""
	})

	cSrcFile = ""
	lastArg := ""
	for _, arg := range builder.args {
		if lastArg != "-o" {
			for _, suffix := range srcFileSuffixes {
				if strings.HasSuffix(arg.value, suffix) {
					cSrcFile = arg.value
					break
				}
			}
		}
		lastArg = arg.value
	}

	if cSrcFile == "" {
		return "", iwyuFlags, iwyuModeNone
	}

	withIWYU, _ := builder.env.getenv("WITH_IWYU")
	if withIWYU == "" {
		withIWYU, builder.args = findWithIWYUFlag(builder.args)
		if withIWYU == "" {
			return cSrcFile, iwyuFlags, iwyuModeNone
		}
	}

	if withIWYU != "1" {
		return cSrcFile, iwyuFlags, iwyuModeError
	}

	return cSrcFile, iwyuFlags, iwyuModeAll
}

func calcIWYUInvocation(env env, clangCmd *command, cSrcFile string, iwyuFlags ...string) (*command, error) {
	resourceDir, err := getClangResourceDir(env, clangCmd.Path)
	if err != nil {
		return nil, err
	}

	iwyuPath := filepath.Join(filepath.Dir(clangCmd.Path), "include-what-you-use")
	args := append([]string{}, iwyuFlags...)
	args = append(args, "-resource-dir="+resourceDir)
	args = append(args, clangCmd.Args...)

	for i := 0; i < len(args); i++ {
		for j := 0; j < len(srcFileSuffixes); j++ {
			if strings.HasSuffix(args[i], srcFileSuffixes[j]) {
				args = append(args[:i], args[i+1:]...)
				break
			}
		}
	}
	args = append(args, cSrcFile)

	return &command{
		Path:       iwyuPath,
		Args:       args,
		EnvUpdates: clangCmd.EnvUpdates,
	}, nil
}

func runIWYU(env env, clangCmd *command, cSrcFile string, extraIWYUFlags []string) error {
	extraIWYUFlags = append(extraIWYUFlags, "-Xiwyu", "--mapping_file=/usr/share/include-what-you-use/libcxx.imp", "-Xiwyu", "--no_fwd_decls")
	iwyuCmd, err := calcIWYUInvocation(env, clangCmd, cSrcFile, extraIWYUFlags...)
	if err != nil {
		return fmt.Errorf("calculating include-what-you-use invocation: %v", err)
	}

	// Note: We pass nil as stdin as we checked before that the compiler
	// was invoked with a source file argument.
	var stderr bytes.Buffer
	stderrWriter := bufio.NewWriter(&stderr)
	exitCode, err := wrapSubprocessErrorWithSourceLoc(iwyuCmd,
		env.run(iwyuCmd, nil, nil, stderrWriter))
	stderrMessage := stderr.String()
	fmt.Fprintln(env.stderr(), stderrMessage)

	if err == nil && exitCode != 0 {
		// Note: We continue on purpose when include-what-you-use fails
		// to maintain compatibility with the previous wrapper.
		fmt.Fprintln(env.stderr(), "include-what-you-use failed")
	}

	iwyuDir := filepath.Join(getCompilerArtifactsDir(env), "linting-output", "iwyu")
	if err := os.MkdirAll(iwyuDir, 0777); err != nil {
		return fmt.Errorf("creating fixes directory at %q: %v", iwyuDir, err)
	}

	f, err := os.CreateTemp(iwyuDir, "*.out")
	if err != nil {
		return fmt.Errorf("making output file for iwyu: %v", err)
	}
	writer := bufio.NewWriter(f)
	if _, err := writer.WriteString(stderrMessage); err != nil {
		return fmt.Errorf("writing output file for iwyu: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flushing output file buffer for iwyu: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("finalizing output file for iwyu: %v", err)
	}

	return err
}
