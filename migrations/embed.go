// Package migrations embeds the SQL schema migrations applied by internal/db.Migrate.
// Files are applied in name order; never edit an applied file, add a new one.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
