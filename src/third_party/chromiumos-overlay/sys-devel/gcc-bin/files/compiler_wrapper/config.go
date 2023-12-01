// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"strconv"
)

type config struct {
	// TODO: Refactor this flag into more generic configuration properties.
	isHostWrapper    bool
	isAndroidWrapper bool
	// Whether to use ccache.
	useCCache bool
	// Whether llvmNext wrapper.
	useLlvmNext bool
	// Flags to add to gcc and clang.
	commonFlags []string
	// Flags to add to gcc only.
	gccFlags []string
	// Flags to add to clang only.
	clangFlags []string
	// Flags to add to clang only, AFTER user flags (cannot be overridden
	// by the user).
	clangPostFlags []string
	// Toolchain root path relative to the wrapper binary.
	rootRelPath string
	// Directory to store errors that were prevented with -Wno-error.
	newWarningsDir string
	// Directory to store nits in when using `WITH_TIDY=tricium`.
	triciumNitsDir string
	// Directory to store crash artifacts in.
	crashArtifactsDir string
	// Version. Only used for printing via -print-cmd.
	version string
}

// Version can be set via a linker flag.
// Values fills config.version.
var Version = ""

// UseCCache can be set via a linker flag.
// Value will be passed to strconv.ParseBool.
// E.g. go build -ldflags '-X config.UseCCache=true'.
var UseCCache = "unknown"

// UseLlvmNext can be set via a linker flag.
// Value will be passed to strconv.ParseBool.
// E.g. go build -ldflags '-X config.UseLlvmNext=true'.
var UseLlvmNext = "unknown"

// ConfigName can be set via a linker flag.
// Value has to be one of:
// - "cros.hardened"
// - "cros.nonhardened"
var ConfigName = "unknown"

// Returns the configuration matching the UseCCache and ConfigName.
func getRealConfig() (*config, error) {
	useCCache, err := strconv.ParseBool(UseCCache)
	if err != nil {
		return nil, wrapErrorwithSourceLocf(err, "invalid format for UseCCache")
	}
	useLlvmNext, err := strconv.ParseBool(UseLlvmNext)
	if err != nil {
		return nil, wrapErrorwithSourceLocf(err, "invalid format for UseLLvmNext")
	}
	config, err := getConfig(ConfigName, useCCache, useLlvmNext, Version)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func isAndroidConfig() bool {
	return ConfigName == "android"
}

func getConfig(configName string, useCCache bool, useLlvmNext bool, version string) (*config, error) {
	cfg := config{}
	switch configName {
	case "cros.hardened":
		cfg = *crosHardenedConfig
	case "cros.nonhardened":
		cfg = *crosNonHardenedConfig
	case "cros.host":
		cfg = *crosHostConfig
	case "android":
		cfg = *androidConfig
	default:
		return nil, newErrorwithSourceLocf("unknown config name: %s", configName)
	}
	cfg.useCCache = useCCache
	cfg.useLlvmNext = useLlvmNext
	if useLlvmNext {
		cfg.clangFlags = append(cfg.clangFlags, llvmNextFlags...)
		cfg.clangPostFlags = append(cfg.clangPostFlags, llvmNextPostFlags...)
	}
	cfg.version = version
	return &cfg, nil
}

// Full hardening.
// Temporarily disable function splitting because of chromium:434751.
var crosHardenedConfig = &config{
	rootRelPath: "../../../../..",
	// Pass "-fcommon" till the packages are fixed to work with new clang/gcc
	// default of "-fno-common", crbug.com/1060413.
	commonFlags: []string{
		"-fcommon",
		"-fstack-protector-strong",
		"-fPIE",
		"-pie",
		"-D_FORTIFY_SOURCE=2",
		"-fno-omit-frame-pointer",
	},
	gccFlags: []string{
		"-fno-reorder-blocks-and-partition",
		"-Wno-unused-local-typedefs",
		"-Wno-maybe-uninitialized",
	},
	// Temporarily disable tautological-*-compare chromium:778316.
	// Temporarily add no-unknown-warning-option to deal with old clang versions.
	// Temporarily disable Wsection since kernel gets a bunch of these. chromium:778867
	// Disable "-faddrsig" since it produces object files that strip doesn't understand, chromium:915742.
	// crbug.com/1103065: -grecord-gcc-switches pollutes the Goma cache;
	//   removed that flag for now.
	clangFlags: []string{
		"-Qunused-arguments",
		"-fno-addrsig",
		"-Wno-tautological-constant-compare",
		"-Wno-tautological-unsigned-enum-zero-compare",
		"-Wno-unknown-warning-option",
		"-Wno-section",
		"-static-libgcc",
		"-fuse-ld=lld",
		"-Wno-final-dtor-non-final-class",
		"-Werror=poison-system-directories",
		"-fexperimental-new-pass-manager",
		"-Wno-compound-token-split-by-macro",
	},
	clangPostFlags: []string{
		"-Wno-implicit-int-float-conversion",
		"-Wno-compound-token-split-by-space",
		"-Wno-string-concatenation",
	},
	newWarningsDir:    "/tmp/fatal_clang_warnings",
	triciumNitsDir:    "/tmp/linting_output/clang-tidy",
	crashArtifactsDir: "/tmp/clang_crash_diagnostics",
}

// Flags to be added to non-hardened toolchain.
var crosNonHardenedConfig = &config{
	rootRelPath: "../../../../..",
	commonFlags: []string{},
	gccFlags: []string{
		"-Wno-maybe-uninitialized",
		"-Wno-unused-local-typedefs",
		"-Wno-deprecated-declarations",
		"-Wtrampolines",
	},
	// Temporarily disable tautological-*-compare chromium:778316.
	// Temporarily add no-unknown-warning-option to deal with old clang versions.
	// Temporarily disable Wsection since kernel gets a bunch of these. chromium:778867
	clangFlags: []string{
		"-Qunused-arguments",
		"-Wno-tautological-constant-compare",
		"-Wno-tautological-unsigned-enum-zero-compare",
		"-Wno-unknown-warning-option",
		"-Wno-section",
		"-static-libgcc",
		"-Wno-final-dtor-non-final-class",
		"-Werror=poison-system-directories",
		"-fexperimental-new-pass-manager",
		"-Wno-compound-token-split-by-macro",
	},
	clangPostFlags: []string{
		"-Wno-implicit-int-float-conversion",
		"-Wno-compound-token-split-by-space",
		"-Wno-string-concatenation",
	},
	newWarningsDir:    "/tmp/fatal_clang_warnings",
	triciumNitsDir:    "/tmp/linting_output/clang-tidy",
	crashArtifactsDir: "/tmp/clang_crash_diagnostics",
}

// Flags to be added to host toolchain.
var crosHostConfig = &config{
	isHostWrapper: true,
	rootRelPath:   "../..",
	// Pass "-fcommon" till the packages are fixed to work with new clang/gcc
	// default of "-fno-common", crbug.com/1060413.
	commonFlags: []string{
		"-fcommon",
	},
	gccFlags: []string{
		"-Wno-maybe-uninitialized",
		"-Wno-unused-local-typedefs",
		"-Wno-deprecated-declarations",
	},
	// Temporarily disable tautological-*-compare chromium:778316.
	// Temporarily add no-unknown-warning-option to deal with old clang versions.
	// crbug.com/1103065: -grecord-gcc-switches pollutes the Goma cache;
	//   removed that flag for now.
	clangFlags: []string{
		"-Qunused-arguments",
		"-fno-addrsig",
		"-fuse-ld=lld",
		"-Wno-unused-local-typedefs",
		"-Wno-deprecated-declarations",
		"-Wno-tautological-constant-compare",
		"-Wno-tautological-unsigned-enum-zero-compare",
		"-Wno-final-dtor-non-final-class",
		"-Werror=poison-system-directories",
		"-Wno-unknown-warning-option",
		"-fexperimental-new-pass-manager",
		"-Wno-compound-token-split-by-macro",
	},
	clangPostFlags: []string{
		"-Wno-implicit-int-float-conversion",
		"-Wno-compound-token-split-by-space",
		"-Wno-string-concatenation",
	},
	newWarningsDir:    "/tmp/fatal_clang_warnings",
	triciumNitsDir:    "/tmp/linting_output/clang-tidy",
	crashArtifactsDir: "/tmp/clang_crash_diagnostics",
}

var androidConfig = &config{
	isHostWrapper:     false,
	isAndroidWrapper:  true,
	rootRelPath:       "./",
	commonFlags:       []string{},
	gccFlags:          []string{},
	clangFlags:        []string{},
	clangPostFlags:    []string{},
	newWarningsDir:    "",
	triciumNitsDir:    "",
	crashArtifactsDir: "",
}
