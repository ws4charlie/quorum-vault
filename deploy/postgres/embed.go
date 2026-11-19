// Package postgresdeploy embeds the SQL that sets up the signing zone's Postgres roles, so qv-migrate and the tests apply exactly what the
// runbook describes.
package postgresdeploy

import _ "embed"

// SigningRoles creates the signing zone's guard roles (NOLOGIN, no rights of their own). Idempotent; roles are cluster-global.
//
//go:embed signing_roles.sql
var SigningRoles string
