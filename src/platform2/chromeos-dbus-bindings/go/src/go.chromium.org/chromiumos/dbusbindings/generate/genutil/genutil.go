// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package genutil provides utility functions for generators to generate a part of the output string.
package genutil

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

// GenerateHeaderGuard generates a string of a header guard.
func GenerateHeaderGuard(path string) string {
	s := "____chromeos_dbus_binding__" + path
	mapping := func(r rune) rune {
		switch {
		case unicode.IsLetter(r):
			return unicode.ToUpper(r)
		case unicode.IsDigit(r):
			return r
		default:
			return '_'
		}
	}
	return strings.Map(mapping, s)
}

func makeNameWithSuffix(itfName, suffix string) string {
	s := strings.Split(itfName, ".")
	return s[len(s)-1] + suffix
}

// MakeInterfaceName makes a name of the class defining the interface.
func MakeInterfaceName(introspectItfName string) string {
	return makeNameWithSuffix(introspectItfName, "Interface")
}

// MakeAdaptorName makes a name of the class serving as a adaptor.
func MakeAdaptorName(introspectItfName string) string {
	return makeNameWithSuffix(introspectItfName, "Adaptor")
}

// MakeProxyName makes a name of the proxy class.
func MakeProxyName(introspectItfName string) string {
	return makeNameWithSuffix(introspectItfName, "Proxy")
}

// MakeProxyInterfaceName returns a name of the proxy interface class.
func MakeProxyInterfaceName(introspectItfName string) string {
	return makeNameWithSuffix(introspectItfName, "ProxyInterface")
}

// MakeFullProxyName returns a fully qualified name of the proxy class.
func MakeFullProxyName(introspectItfName string) string {
	return MakeFullItfName(introspectItfName) + "Proxy"
}

// MakeFullProxyName returns a fully qualified name of the proxy interface class.
func MakeFullProxyInterfaceName(introspectItfName string) string {
	return MakeFullItfName(introspectItfName) + "ProxyInterface"
}

// MakeTypeName returns the last component of the qualified name.
func MakeTypeName(introspectItfName string) string {
	return makeNameWithSuffix(introspectItfName, "")
}

// MakeFullItfName makes a full name of interface in C++ style.
func MakeFullItfName(introspectItfName string) string {
	return strings.Replace(introspectItfName, ".", "::", -1)
}

// ExtractNameSpaces extract the namespace parts of the interface from the interface name.
func ExtractNameSpaces(introspectItfName string) []string {
	s := strings.Split(introspectItfName, ".")
	return s[:len(s)-1]
}

// Reverse overwrites the slice in reverse order.
func Reverse(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// Nindent returns string with indent, prefixed by a NL.
func Nindent(i int, s string) string {
	lines := strings.Split(s, "\n")
	indent := "\n" + strings.Repeat(" ", i)
	return indent + strings.Join(lines, indent)
}

var indentRE = regexp.MustCompile(`^[ \t]+`)

// FormatComment removes extraneous white space, inserts a double slash and adds an indent of |indent| characters
// to each line for the string.
// This function tries to retain indentation in the comments to maintain the comment layout.
func FormatComment(docString introspect.DocString, indent int) string {
	lines := strings.Split(string(docString), "\n")

	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	var i int
	for i = 0; i < len(lines); i++ {
		if lines[i] != "" {
			break
		}
	}
	lines = lines[i:]
	for i = len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			break
		}
	}
	lines = lines[:i+1]

	trimPrefix := ""
	if len(lines) > 0 {
		trimPrefix = indentRE.FindString(lines[0])
	}

	var ret strings.Builder
	prefix := strings.Repeat(" ", indent) + "//"
	for _, line := range lines {
		ret.WriteString(prefix)
		if line != "" {
			ret.WriteString(" ")
			if strings.HasPrefix(line, trimPrefix) {
				line = line[len(trimPrefix):]
			} else {
				line = strings.TrimLeft(line, " \t")
			}
			ret.WriteString(line)
		}
		ret.WriteRune('\n')
	}
	return ret.String()
}

// ArgName makes a name of a method argument.
func ArgName(prefix, argName string, argIndex int) string {
	if argName == "" {
		return fmt.Sprintf("%s_%d", prefix, argIndex)
	}
	return fmt.Sprintf("%s_%s", prefix, argName)
}

var insertRE = regexp.MustCompile(`([^A-Z])([A-Z])`)

// MakeVariableName discards the namespace parts and converts CamelCase name to google_style variable name.
func MakeVariableName(s string) string {
	split := strings.Split(s, ".")
	camelCase := split[len(split)-1]

	f := func(s string) string {
		return fmt.Sprintf("%c_%c", s[0], s[1])
	}
	return strings.ToLower(insertRE.ReplaceAllStringFunc(camelCase, f))
}
