// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package methodnames outputs a list of method names based on introspects.
package methodnames

import (
	"io"
	"strings"
	"text/template"

	"go.chromium.org/chromiumos/dbusbindings/generate/genutil"
	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

var funcMap = template.FuncMap{
	"reverse": genutil.Reverse,
	"split":   strings.Split,
}

const templateText = `
{{- range .}}{{range $itf := .Interfaces}}
{{range split $itf.Name "." -}}
namespace {{.}} {
{{end -}}
{{range $itf.Methods -}}
const char k{{.Name}}Method[] = "{{.Name}}";
{{end -}}
{{range split $itf.Name "." | reverse -}}
}  // namespace {{.}}
{{end -}}
{{end}}{{end -}}
`

// Generate prints a list of method names included in introspects.
func Generate(introspects []introspect.Introspection, f io.Writer) error {
	tmpl, err := template.New("methodNames").Funcs(funcMap).Parse(templateText)
	if err != nil {
		return err
	}
	return tmpl.Execute(f, introspects)
}
