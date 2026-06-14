package secretshare

import (
	"context"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/approval"
	"trustctl.io/trustctl/internal/auditsink"
)

func TestOneTimeLinkSelfDestructs(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", rec, nil)
	tok, err := s.Create(ctx, []byte("the-secret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.View(ctx, tok)
	if err != nil || string(got) != "the-secret" {
		t.Fatalf("first view = %q (err %v)", got, err)
	}
	// Second view returns nothing.
	if _, err := s.View(ctx, tok); err == nil {
		t.Error("second view succeeded — link did not self-destruct")
	}
	if rec.Count("secret.share.viewed") != 1 {
		t.Error("view not audited")
	}
}

func TestExpiredLinkReturnsNothing(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := New("t1", nil, clock)
	tok, _ := s.Create(context.Background(), []byte("x"), time.Minute)
	now = now.Add(2 * time.Minute) // past expiry
	if _, err := s.View(context.Background(), tok); err == nil {
		t.Error("expired link returned a secret")
	}
}

func TestSecretChangeRequiresApproval(t *testing.T) {
	ctx := context.Background()
	applied := false
	mgr, err := NewChangeApprovals("t1", func(_ context.Context, _, resource string) (string, error) {
		applied = true
		return "change-" + resource, nil
	}, &auditsink.Recorder{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.RequestIssuance(ctx, approval.RequestSpec{ID: "chg-1", Resource: "secret:app/db", Requester: "alice"}); err != nil {
		t.Fatal(err)
	}
	// Not applied until dual-control approvals complete.
	if _, _ = mgr.Approve(ctx, "t1", "chg-1", "bob"); applied {
		t.Error("change applied after a single approval")
	}
	if _, err := mgr.Approve(ctx, "t1", "chg-1", "carol"); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Error("change not applied after dual-control approval")
	}
}
