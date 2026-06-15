-- 0022_certificates_expiry_keyset.sql — make the list-expiring-paginated query
-- index-friendly (SPINE-006).
--
-- The combined "expiring before T, paginated" inventory query used a keyset on the
-- primary key (WHERE id > cursor AND not_after < T ORDER BY id), which cannot ride
-- the (tenant_id, not_after) expiry index: ordering by id forces a scan of the PK,
-- discarding every non-matching row (EXPLAIN showed thousands of "Rows Removed by
-- Filter" per page on a 50k-row tenant). The store query now orders by
-- (not_after, id) and keysets on that pair when expiring_before is set, so it can
-- walk this composite index in order with near-zero rows removed.
--
-- (tenant_id, not_after, id) extends the existing (tenant_id, not_after) expiry
-- index with id as the keyset tie-breaker, giving a total order the paginated
-- expiry query rides directly. The plain (no-filter) page keeps using the primary
-- key. RLS and grants are inherited from 0006 (certificates).

CREATE INDEX IF NOT EXISTS certificates_expiry_keyset_idx
    ON certificates (tenant_id, not_after, id);
