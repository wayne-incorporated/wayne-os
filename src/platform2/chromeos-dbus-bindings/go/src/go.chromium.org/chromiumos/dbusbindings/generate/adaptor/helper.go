// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package adaptor

import (
	"fmt"
	"strings"

	"go.chromium.org/chromiumos/dbusbindings/generate/genutil"
	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

func makeMethodRetType(method introspect.Method) (string, error) {
	switch method.Kind() {
	case introspect.MethodKindSimple:
		if outputArguments := method.OutputArguments(); len(outputArguments) == 1 {
			baseType, err := outputArguments[0].BaseType()
			if err != nil {
				return "", err
			}
			return baseType, nil
		}
	case introspect.MethodKindNormal:
		return "bool", nil
	}
	return "void", nil
}

func makeMethodParams(method introspect.Method) ([]string, error) {
	var methodParams []string
	inputArguments := method.InputArguments()
	outputArguments := method.OutputArguments()

	switch method.Kind() {
	case introspect.MethodKindSimple:
		if len(outputArguments) == 1 {
			outputArguments = nil
			// As we can see from makeMethodRetType function,
			// the only out argument is treated as a normal return value.
		}
	case introspect.MethodKindNormal:
		methodParams = append(methodParams, "brillo::ErrorPtr* error")
		if method.IncludeDBusMessage() {
			methodParams = append(methodParams, "dbus::Message* message")
		}
	case introspect.MethodKindAsync:
		var outTypes []string
		for _, arg := range outputArguments {
			baseType, err := arg.BaseType()
			if err != nil {
				return nil, err
			}
			outTypes = append(outTypes, baseType)
		}
		param := fmt.Sprintf(
			"std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<%s>> response",
			strings.Join(outTypes, ", "))
		methodParams = append(methodParams, param)
		if method.IncludeDBusMessage() {
			methodParams = append(methodParams, "dbus::Message* message")
		}
		outputArguments = nil
	case introspect.MethodKindRaw:
		methodParams = append(methodParams, "dbus::MethodCall* method_call")
		methodParams = append(methodParams, "brillo::dbus_utils::ResponseSender sender")
		// Raw methods don't take static parameters or return values directly.
		inputArguments = nil
		outputArguments = nil
	}

	index := 1
	for _, c := range []struct {
		args        []introspect.MethodArg
		makeArgType func(*introspect.MethodArg) (string, error)
		prefix      string
	}{
		{inputArguments, (*introspect.MethodArg).InArgType, "in"},
		{outputArguments, (*introspect.MethodArg).OutArgType, "out"},
	} {
		for _, arg := range c.args {
			paramType, err := c.makeArgType(&arg)
			if err != nil {
				return nil, err
			}
			paramName := genutil.ArgName(c.prefix, arg.Name, index)
			index++
			methodParams = append(methodParams, fmt.Sprintf("%s %s", paramType, paramName))
		}
	}

	return methodParams, nil
}

func makeAddHandlerName(method introspect.Method) string {
	switch method.Kind() {
	case introspect.MethodKindSimple:
		return "AddSimpleMethodHandler"
	case introspect.MethodKindNormal:
		if method.IncludeDBusMessage() {
			return "AddSimpleMethodHandlerWithErrorAndMessage"
		}
		return "AddSimpleMethodHandlerWithError"
	case introspect.MethodKindAsync:
		if method.IncludeDBusMessage() {
			return "AddMethodHandlerWithMessage"
		}
		return "AddMethodHandler"
	case introspect.MethodKindRaw:
		return "AddRawMethodHandler"
	}
	return ""
}

func makePropertyWriteAccess(property introspect.Property) string {
	switch property.Access {
	case "write":
		return "kWriteOnly"
	case "readwrite":
		return "kReadWrite"
	case "read":
		return ""
	}
	return ""
}

func makeSignalParams(signal introspect.Signal) ([]string, error) {
	var params []string
	index := 1
	for _, arg := range signal.Args {
		// We are the sender for signals, so pretend we're a proxy
		// when generating the type.
		paramType, err := arg.InArgType()
		if err != nil {
			return nil, err
		}
		paramName := genutil.ArgName("in", arg.Name, index)
		index++
		params = append(params, fmt.Sprintf("%s %s", paramType, paramName))
	}
	return params, nil
}

func makeSignalArgNames(signal introspect.Signal) string {
	var paramNames []string
	index := 1
	for _, arg := range signal.Args {
		paramName := genutil.ArgName("in", arg.Name, index)
		index++
		paramNames = append(paramNames, paramName)
	}
	return strings.Join(paramNames, ", ")
}

func makeDBusSignalParams(signal introspect.Signal) ([]string, error) {
	var params []string
	for _, arg := range signal.Args {
		param, err := arg.BaseType()
		if err != nil {
			return nil, err
		}
		if arg.Name != "" {
			param += fmt.Sprintf(" /*%s*/", arg.Name)
		}
		params = append(params, param)
	}
	return params, nil
}
