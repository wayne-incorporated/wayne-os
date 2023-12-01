// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package proxy

import (
	"fmt"
	"strings"

	"go.chromium.org/chromiumos/dbusbindings/generate/genutil"
	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

type param struct {
	Type, Name string
}

func makeMethodParams(offset int, args []introspect.MethodArg) ([]param, error) {
	var ret []param
	for i, a := range args {
		argType, prefix := a.InArgType, "in"
		if a.Direction == "out" {
			argType, prefix = a.OutArgType, "out"
		}
		t, err := argType()
		if err != nil {
			return nil, err
		}
		// The number-suffix is 1-indexed.
		ret = append(ret, param{t, genutil.ArgName(prefix, a.Name, i+offset+1)})
	}

	return ret, nil
}

func makeMethodCallbackType(args []introspect.MethodArg) (string, error) {
	var params []string
	for _, a := range args {
		t, err := a.CallbackType()
		if err != nil {
			return "", err
		}
		if a.Name == "" {
			params = append(params, t)
		} else {
			params = append(params, fmt.Sprintf("%s /*%s*/", t, a.Name))
		}
	}
	return fmt.Sprintf("base::OnceCallback<void(%s)>", strings.Join(params, ", ")), nil

}

func makeMockMethodParams(args []introspect.MethodArg) ([]string, error) {
	var ret []string
	for _, a := range args {
		argType, prefix := a.InArgType, "in"
		if a.Direction == "out" {
			argType, prefix = a.OutArgType, "out"
		}
		t, err := argType()
		if err != nil {
			return nil, err
		}
		if a.Name == "" {
			ret = append(ret, t)
		} else {
			ret = append(ret, fmt.Sprintf("%s /*%s_%s*/", t, prefix, a.Name))
		}
	}

	return ret, nil
}

// Returns stringified C++ type for signal callback.
func makeSignalCallbackType(args []introspect.SignalArg) (string, error) {
	if len(args) == 0 {
		return "base::RepeatingClosure", nil
	}

	var lines []string
	for _, a := range args {
		line, err := a.CallbackType()
		if err != nil {
			return "", err
		}
		lines = append(lines, line)
	}
	const (
		prefix = "const base::RepeatingCallback<void("
		suffix = ")>&"
	)
	indent := strings.Repeat(" ", len(prefix))
	return fmt.Sprintf("%s%s%s", prefix, strings.Join(lines, ",\n"+indent), suffix), nil
}

// extractInterfacesWithProperties returns an array of Interfaces that have Properties.
func extractInterfacesWithProperties(iss []introspect.Introspection) []introspect.Interface {
	var ret []introspect.Interface
	for _, is := range iss {
		for _, itf := range is.Interfaces {
			if len(itf.Properties) > 0 {
				ret = append(ret, itf)
			}
		}
	}
	return ret
}
