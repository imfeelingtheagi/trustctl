package store

// Every data-manipulation query in a repository package must filter on
// tenant_id (AN-1). The "Good" constants are clean; the "Bad" ones are flagged.
const (
	listGood = "SELECT id, name FROM certificates WHERE tenant_id = $1 ORDER BY name"
	listBad  = "SELECT id, name FROM certificates WHERE owner = $1" // want "does not filter on tenant_id"

	updateGood = "UPDATE certificates SET revoked = true WHERE tenant_id = $1 AND id = $2"
	updateBad  = "UPDATE certificates SET revoked = true WHERE id = $1" // want "does not filter on tenant_id"

	deleteBad = "DELETE FROM certificates WHERE id = $1" // want "does not filter on tenant_id"

	insertGood = "INSERT INTO certificates (tenant_id, id, name) VALUES ($1, $2, $3)"
	insertBad  = "INSERT INTO certificates (id, name) VALUES ($1, $2)" // want "does not filter on tenant_id"

	// Not a DML statement, so it is not subject to the rule.
	ddl = "CREATE TABLE certificates (id uuid primary key)"

	// System (non-tenant) tables are exempt: no tenant_id is expected.
	migCheck  = "SELECT version FROM schema_migrations"
	migRecord = "INSERT INTO schema_migrations (version) VALUES ($1)"

	// Session/lock control functions read no table, so they are exempt: the
	// migration advisory lock (AN-1 R2.5) carries no tenant_id.
	migLock   = "SELECT pg_advisory_lock($1)"
	migUnlock = "SELECT pg_advisory_unlock($1)"
)
