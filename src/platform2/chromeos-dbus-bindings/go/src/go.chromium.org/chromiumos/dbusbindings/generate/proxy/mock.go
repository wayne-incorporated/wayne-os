// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package proxy

import (
	"io"
	"text/template"

	"go.chromium.org/chromiumos/dbusbindings/generate/genutil"
	"go.chromium.org/chromiumos/dbusbindings/introspect"
	"go.chromium.org/chromiumos/dbusbindings/serviceconfig"
)

const mockTemplateText = `// Automatic generation of D-Bus interface mock proxies for:
{{range .Introspects}}{{range .Interfaces -}}
//  - {{.Name}}
{{end}}{{end -}}

#ifndef {{.HeaderGuard}}
#define {{.HeaderGuard}}
#include <string>
#include <vector>

#include <base/functional/callback_forward.h>
#include <base/logging.h>
#include <brillo/any.h>
#include <brillo/errors/error.h>
#include <brillo/variant_dictionary.h>
#include <gmock/gmock.h>
{{- if $.ProxyFilePath}}

#include "{{$.ProxyFilePath}}"
{{- end}}
{{range $introspect := .Introspects}}{{range $itf := .Interfaces -}}
{{- $itfName := makeProxyInterfaceName .Name -}}

{{- if (not $.ProxyFilePath)}}
{{template "proxyInterface" (makeProxyInterfaceArgs . $.ObjectManagerName) }}
{{- end}}
{{range extractNameSpaces .Name -}}
namespace {{.}} {
{{end}}
// Mock object for {{$itfName}}.
{{- $mockName := makeProxyName .Name | printf "%sMock" }}
class {{$mockName}} : public {{$itfName}} {
 public:
  {{$mockName}}() = default;
  {{$mockName}}(const {{$mockName}}&) = delete;
  {{$mockName}}& operator=(const {{$mockName}}&) = delete;
{{range .Methods -}}
{{- $inParams := makeMockMethodParams .InputArguments -}}
{{- $outParams := makeMockMethodParams .OutputArguments -}}
{{- $arity := gmockArity (len $inParams) (len $outParams) -}}
{{- /* TODO(crbug.com/983008): The following format is to make the output compatible with C++. */}}
{{- if ge $arity.Sync 11}}
{{- /* TODO(crbug.com/983008): Old gmock does not support arity >= 11. So this is workaround. */ -}}
{{- $indent := repeat " " (add (len "  bool (") (len .Name))}}
  bool {{.Name}}(
{{- range $inParams -}}
{{.}},
{{$indent}}{{end -}}
{{- range $outParams -}}
{{.}},
{{$indent}}{{end -}}
brillo::ErrorPtr* /*error*/,
{{$indent}}int /*timeout_ms*/) override {
    LOG(WARNING) << "{{.Name}}(): gmock can't handle methods with {{$arity.Sync}} arguments. You can override this method in a subclass if you need to.";
    return false;
  }
{{- else}}
  MOCK_METHOD{{$arity.Sync}}({{.Name}},
               {{if ge $arity.Sync 10}} {{end}}bool(
{{- range $inParams -}}
{{.}},
                    {{if ge $arity.Sync 10}} {{end}}{{end -}}
{{- range $outParams -}}
{{.}},
                    {{if ge $arity.Sync 10}} {{end}}{{end -}}
                    brillo::ErrorPtr* /*error*/,
                    {{if ge $arity.Sync 10}} {{end}}int /*timeout_ms*/));
{{- end}}
{{- if ge $arity.Async 11}}
{{- /* TODO(crbug.com/983008): Old gmock does not support arity >= 11. So this is workaround. */ -}}
{{- $indent := repeat " " (add 13 (len .Name))}}
  void {{.Name}}Async(
{{- range $inParams -}}
{{.}},
{{$indent}}{{end -}}
{{makeMethodCallbackType .OutputArguments}} /*success_callback*/,
{{$indent}}base::OnceCallback<void(brillo::Error*)> /*error_callback*/,
{{$indent}}int /*timeout_ms*/) override {
    LOG(WARNING) << "{{.Name}}Async(): gmock can't handle methods with {{$arity.Async}} arguments. You can override this method in a subclass if you need to.";
  }
{{- else}}
  MOCK_METHOD{{$arity.Async}}({{.Name}}Async,
               {{if ge $arity.Async 10}} {{end}}void(
{{- range $inParams -}}
{{.}},
                    {{if ge $arity.Async 10}} {{end}}{{end -}}
                    {{makeMethodCallbackType .OutputArguments}} /*success_callback*/,
                    {{if ge $arity.Async 10}} {{end}}base::OnceCallback<void(brillo::Error*)> /*error_callback*/,
                    {{if ge $arity.Async 10}} {{end}}int /*timeout_ms*/));
{{- end}}
{{- end}}
{{- range .Signals}}
  void Register{{.Name}}SignalHandler(
    {{- /* TODO(crbug.com/983008): fix the indent to meet style guide. */ -}}
    {{- makeSignalCallbackType .Args | nindent 4}} signal_callback,
    dbus::ObjectProxy::OnConnectedCallback on_connected_callback) {
    DoRegister{{.Name}}SignalHandler(signal_callback, &on_connected_callback);
  }
  MOCK_METHOD2(DoRegister{{.Name}}SignalHandler,
               void({{makeSignalCallbackType .Args | nindent 20 | trimLeft " \n"}} /*signal_callback*/,
                    dbus::ObjectProxy::OnConnectedCallback* /*on_connected_callback*/));
{{- end}}
{{- range .Properties}}
{{- $name := makePropertyVariableName . | makeVariableName -}}
{{- $type := makeProxyInArgTypeProxy . }}
  MOCK_CONST_METHOD0({{$name}}, {{$type}}());
  MOCK_CONST_METHOD0(is_{{$name}}_valid, bool());
{{- if eq .Access "readwrite"}}
  MOCK_METHOD2(set_{{$name}}, void({{$type}}, base::OnceCallback<void(bool)>));
{{- end}}
{{- end}}
  MOCK_CONST_METHOD0(GetObjectPath, const dbus::ObjectPath&());
  MOCK_CONST_METHOD0(GetObjectProxy, dbus::ObjectProxy*());
{{- if .Properties}}
{{- if $.ObjectManagerName }}
  MOCK_METHOD1(SetPropertyChangedCallback,
               void(const base::RepeatingCallback<void({{$itfName}}*, const std::string&)>&));
{{- else}}
  MOCK_METHOD1(InitializeProperties,
               void(const base::RepeatingCallback<void({{$itfName}}*, const std::string&)>&));
{{- end}}
{{- end}}
};
{{range extractNameSpaces .Name | reverse -}}
}  // namespace {{.}}
{{end}}
{{- end}}
{{- end}}
#endif  // {{.HeaderGuard}}
`

// GenerateMock outputs the header file containing gmock proxy interfaces into f.
// outputFilePath is used to make a unique header guard.
func GenerateMock(introspects []introspect.Introspection, f io.Writer, outputFilePath string, proxyFilePath string, config serviceconfig.Config) error {
	mockFuncMap := make(template.FuncMap)
	for k, v := range funcMap {
		mockFuncMap[k] = v
	}

	type gmockArity struct {
		Sync, Async int
	}
	mockFuncMap["gmockArity"] = func(nInArgs, nOutArgs int) gmockArity {
		return gmockArity{
			Sync:  nInArgs + nOutArgs + 2, // error and timeout.
			Async: nInArgs + 3,            // success_callback, error_callback and timeout
		}
	}

	tmpl, err := template.New("mock").Funcs(mockFuncMap).Parse(mockTemplateText)
	if err != nil {
		return err
	}

	if _, err := tmpl.Parse(proxyInterfaceTemplate); err != nil {
		return err
	}

	var omName string
	if config.ObjectManager != nil {
		omName = config.ObjectManager.Name
	}

	headerGuard := genutil.GenerateHeaderGuard(outputFilePath)
	return tmpl.Execute(f, struct {
		Introspects       []introspect.Introspection
		HeaderGuard       string
		ProxyFilePath     string
		ServiceName       string
		ObjectManagerName string
	}{
		Introspects:       introspects,
		HeaderGuard:       headerGuard,
		ProxyFilePath:     proxyFilePath,
		ServiceName:       config.ServiceName,
		ObjectManagerName: omName,
	})
}
