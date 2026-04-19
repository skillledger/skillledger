package schema

import "embed"

//go:embed schemas/*.json schemas/profiles/*.json
var SchemaFS embed.FS
