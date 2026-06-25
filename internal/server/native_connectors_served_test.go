package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/azurekv/azurekvtest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedNativeConnectorRegistryDeploysToACMAndAzureKVEmulators(t *testing.T) {
	const (
		awsAccessKey = "AKIDCLM05"
		awsSecretKey = "CLM05SecretKeyForSigV4Only"
		acmTargetARN = "arn:aws:acm:us-east-1:123456789012:certificate/clm-05"
		azureToken   = "clm-05-azure-token"
		azureCert    = "clm-05-web"
	)

	acmSrv := acmtest.New(awsAccessKey, awsSecretKey)
	defer acmSrv.Close()
	kvSrv := azurekvtest.New(azureToken)
	defer kvSrv.Close()

	reg := connector.NewRegistry(func(name string) connector.Ops {
		switch name {
		case "aws-acm":
			return connector.NewHTTPOps(acmSrv.Client())
		case "azure-keyvault":
			return connector.NewHTTPOps(kvSrv.Client())
		default:
			return connector.NewHTTPOps(nil)
		}
	})
	reg.Register(acm.New("us-east-1", acm.Credentials{
		AccessKeyID:     awsAccessKey,
		SecretAccessKey: []byte(awsSecretKey),
	}, acm.WithEndpoint(acmSrv.URL())))
	reg.Register(azurekv.New(kvSrv.URL(), azurekv.StaticToken([]byte(azureToken))))

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = reg
	})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read")

	certPEM, keyPEM := servedNativeDeployCredential(t, h, "clm-05.served.test")
	defer secret.Wipe(keyPEM)
	if err := crypto.VerifyCertKeyMatchPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("test credential mismatch: %v", err)
	}

	enqueueServedConnectorDeploy(t, h, "clm-05-acm", "aws-acm", connector.NewDeployment(acmTargetARN, certPEM, keyPEM))
	enqueueServedConnectorDeploy(t, h, "clm-05-azure-kv", "azure-keyvault", connector.NewDeployment(azureCert, certPEM, keyPEM))
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain native connector outbox: %v", err)
	}

	acmImport, ok := acmSrv.Imported(acmTargetARN)
	if !ok {
		t.Fatalf("served aws-acm deploy did not import into the ACM emulator")
	}
	if !bytes.Equal(acmImport.Certificate, certPEM) || !bytes.Equal(acmImport.PrivateKey, keyPEM) {
		t.Fatalf("ACM emulator received the wrong credential")
	}
	kvImport, ok := kvSrv.Imported(azureCert)
	if !ok {
		t.Fatalf("served azure-keyvault deploy did not import into the Key Vault emulator")
	}
	if !bytes.Contains(kvImport.PEM, keyPEM) || !bytes.Contains(kvImport.PEM, certPEM) {
		t.Fatalf("Key Vault emulator received bundle without the issued cert and key")
	}

	deliveries := connectorDeliveries(t, h, tok)
	want := map[string]string{
		"aws-acm":        acmTargetARN,
		"azure-keyvault": azureCert,
	}
	for _, got := range deliveries.Items {
		if want[got.Connector] != got.Target {
			continue
		}
		if got.Status != "delivered" || got.Reason != "native_delivered" || got.Fingerprint == "" {
			t.Fatalf("bad native connector receipt for %s: %+v", got.Connector, got)
		}
		delete(want, got.Connector)
	}
	if len(want) != 0 {
		t.Fatalf("missing delivered connector receipts for %+v; got %s", want, deliveries.Raw)
	}
	if !h.hasEvent(t, "connector.delivery.recorded") {
		t.Fatal("native connector deployment did not emit connector.delivery.recorded")
	}
}

func servedNativeDeployCredential(t *testing.T, h *servedHarness, cn string) ([]byte, []byte) {
	t.Helper()
	keyDER, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate deploy key: %v", err)
	}
	defer secret.Wipe(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	signer, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, keyDER)
	if err != nil {
		secret.Wipe(keyPEM)
		t.Fatalf("load deploy signer: %v", err)
	}
	defer signer.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: cn,
		DNSNames:   []string{cn},
	}, signer)
	if err != nil {
		secret.Wipe(keyPEM)
		t.Fatalf("create deploy CSR: %v", err)
	}
	certPEM, err := h.srv.IssueLeaf(t.Context(), csrDER, time.Hour)
	if err != nil {
		secret.Wipe(keyPEM)
		t.Fatalf("issue deploy leaf: %v", err)
	}
	return certPEM, keyPEM
}

func enqueueServedConnectorDeploy(t *testing.T, h *servedHarness, idemKey, connectorName string, dep connector.Deployment) {
	t.Helper()
	payload, err := connector.EncodeDeploy(connectorName, dep)
	if err != nil {
		t.Fatalf("encode connector deploy: %v", err)
	}
	ctx := context.Background()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       h.tenant,
			Destination:    "connector.deploy",
			IdempotencyKey: idemKey,
			Payload:        payload,
		})
		return err
	}); err != nil {
		t.Fatalf("enqueue connector deploy: %v", err)
	}
}

func connectorDeliveries(t *testing.T, h *servedHarness, tok string) connectorDeliveryList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/deliveries", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list connector deliveries: status %d body %s", status, body)
	}
	var out connectorDeliveryList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode connector deliveries: %v (%s)", err, body)
	}
	return out
}
