package server

import (
	"context"
	"errors"
	"fmt"

	"certctl.io/certctl/internal/agent/enroll"
	"certctl.io/certctl/internal/api"
)

// enrollAuthority adapts the agent-enrollment authority to the API's minimal
// interfaces (api.BootstrapTokenIssuer + api.BootstrapEnroller), translating the
// enroll package's sentinel into the API's so the api package never imports the
// enrollment transport stack. The authority's CA is in-process today (see
// internal/agent/enroll); custodying its key in the signer (AN-4) is a follow-up.
type enrollAuthority struct{ a *enroll.Authority }

func (e enrollAuthority) IssueBootstrapToken() (string, error) { return e.a.IssueBootstrapToken() }

func (e enrollAuthority) EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error) {
	chain, err := e.a.EnrollBootstrap(ctx, token, csrDER)
	if errors.Is(err, enroll.ErrBadToken) {
		return nil, fmt.Errorf("%w", api.ErrInvalidBootstrapToken)
	}
	return chain, err
}

func (e enrollAuthority) CABundlePEM() []byte { return e.a.CABundlePEM() }
