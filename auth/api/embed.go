// Package api содержит описание OpenAPI и страницу Swagger UI.
package api

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte

//go:embed swagger.html
var SwaggerUI []byte
