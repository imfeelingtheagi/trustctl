package acme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"trustctl.io/trustctl/internal/protocols/ari"
)

// Identifier is a single ACME order identifier (RFC 8555 §7.1.4). This server
// issues for DNS identifiers only.
type Identifier struct {
	Type  string
	Value string
}

// OrderRequest is the decoded, validated body of a newOrder request
// (RFC 8555 §7.4).
type OrderRequest struct {
	Identifiers []Identifier
	Replaces    string // ARI (RFC 9773): the certificate identifier this order renews
}

// ParseOrderRequest decodes and validates a newOrder payload. It is the single
// parser the newOrder handler uses, exported so it can be fuzzed against the
// exact production code path. It fails closed: a malformed body, no identifiers,
// a non-DNS identifier type, an empty identifier value, or an invalid ARI
// `replaces` is rejected rather than turned into a half-understood order. Unknown
// JSON fields are tolerated (RFC 8555 permits notBefore/notAfter and forward-
// compatible extensions).
func ParseOrderRequest(payload []byte) (OrderRequest, error) {
	var raw struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		Replaces string `json:"replaces"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return OrderRequest{}, fmt.Errorf("acme: malformed newOrder: %w", err)
	}
	if len(raw.Identifiers) == 0 {
		return OrderRequest{}, fmt.Errorf("acme: newOrder requests no identifiers")
	}
	out := OrderRequest{Replaces: raw.Replaces}
	for i, id := range raw.Identifiers {
		if id.Type != "dns" {
			return OrderRequest{}, fmt.Errorf("acme: identifier %d has unsupported type %q (only dns)", i, id.Type)
		}
		if id.Value == "" {
			return OrderRequest{}, fmt.Errorf("acme: identifier %d has empty value", i)
		}
		out.Identifiers = append(out.Identifiers, Identifier{Type: id.Type, Value: id.Value})
	}
	if raw.Replaces != "" && !ari.ValidCertID(raw.Replaces) {
		return OrderRequest{}, fmt.Errorf("acme: replaces is not a valid certificate identifier")
	}
	return out, nil
}

// Domains returns the identifier values in order.
func (o OrderRequest) Domains() []string {
	ds := make([]string, 0, len(o.Identifiers))
	for _, id := range o.Identifiers {
		ds = append(ds, id.Value)
	}
	return ds
}

// ParseFinalizeRequest decodes a finalize payload (RFC 8555 §7.4) and returns the
// DER-encoded CSR. It is exported so it can be fuzzed against the exact
// production path. It fails closed on a malformed body, a non-base64url CSR, or
// an empty CSR.
func ParseFinalizeRequest(payload []byte) ([]byte, error) {
	var raw struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("acme: malformed finalize: %w", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(raw.CSR)
	if err != nil {
		return nil, fmt.Errorf("acme: finalize CSR is not base64url: %w", err)
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("acme: finalize CSR is empty")
	}
	return der, nil
}
