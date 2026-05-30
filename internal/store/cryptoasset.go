package store

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// CryptoAsset is one classified cryptographic observation in the CBOM (F52).
type CryptoAsset struct {
	ID                string
	TenantID          string
	Kind              string
	Location          string
	Algorithm         string
	KeyBits           int
	Protocol          string
	Cipher            string
	Library           string
	Strength          string
	QuantumVulnerable bool
	OutOfPolicy       bool
	Reasons           []string
	CreatedAt         time.Time
}

// signature identifies an asset within a tenant: the kind, location, and the
// specific crypto fact it describes. Re-scanning the same usage refreshes the
// existing row rather than duplicating it.
func (a CryptoAsset) signature() string {
	return strings.Join([]string{a.Kind, a.Location, a.Algorithm, strconv.Itoa(a.KeyBits), a.Protocol, a.Cipher}, "|")
}

// UpsertCryptoAsset inserts or refreshes a crypto asset by (tenant, signature),
// returning it with its id and created_at. Tenant-scoped (RLS-enforced).
func (s *Store) UpsertCryptoAsset(ctx context.Context, a CryptoAsset) (CryptoAsset, error) {
	reasons := a.Reasons
	if reasons == nil {
		reasons = []string{}
	}
	err := s.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO crypto_assets
			        (id, tenant_id, signature, kind, location, algorithm, key_bits, protocol, cipher,
			         library, strength, quantum_vulnerable, out_of_policy, reasons)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			 ON CONFLICT (tenant_id, signature) DO UPDATE
			    SET key_bits = EXCLUDED.key_bits, library = EXCLUDED.library, strength = EXCLUDED.strength,
			        quantum_vulnerable = EXCLUDED.quantum_vulnerable, out_of_policy = EXCLUDED.out_of_policy,
			        reasons = EXCLUDED.reasons
			 RETURNING id::text, created_at`,
			a.TenantID, a.signature(), a.Kind, a.Location, a.Algorithm, a.KeyBits, a.Protocol, a.Cipher,
			a.Library, a.Strength, a.QuantumVulnerable, a.OutOfPolicy, reasons).
			Scan(&a.ID, &a.CreatedAt)
	})
	return a, err
}

// ListCryptoAssets returns every crypto asset for the tenant, ordered.
func (s *Store) ListCryptoAssets(ctx context.Context, tenantID string) ([]CryptoAsset, error) {
	var out []CryptoAsset
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, kind, location, algorithm, key_bits, protocol, cipher,
			        library, strength, quantum_vulnerable, out_of_policy, reasons, created_at
			   FROM crypto_assets WHERE tenant_id = $1 ORDER BY location, algorithm, protocol, cipher`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a CryptoAsset
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Kind, &a.Location, &a.Algorithm, &a.KeyBits,
				&a.Protocol, &a.Cipher, &a.Library, &a.Strength, &a.QuantumVulnerable, &a.OutOfPolicy,
				&a.Reasons, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}
