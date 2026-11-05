// Package api contains the published REST contract and Swagger UI entry point.
package api

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte

//go:embed docs.html
var Docs []byte
