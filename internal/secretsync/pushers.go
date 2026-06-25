package secretsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// HTTPDoer is the small seam concrete sync pushers use for real APIs and fixtures.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// GitHubActionsConfig configures a GitHub Actions secret sync destination. The
// acceptance fixture accepts encoded_value directly; production operators should
// still prefer scoped repository/environment tokens and keep token bytes in []byte.
type GitHubActionsConfig struct {
	Endpoint   string
	HTTPClient HTTPDoer
	Owner      string
	Repo       string
	Token      []byte
}

type GitHubActionsPusher struct {
	endpoint string
	doer     HTTPDoer
	owner    string
	repo     string
	token    []byte
}

func NewGitHubActionsPusher(cfg GitHubActionsConfig) (*GitHubActionsPusher, error) {
	if cfg.Endpoint == "" || cfg.Owner == "" || cfg.Repo == "" {
		return nil, errors.New("secretsync: github endpoint, owner, and repo are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	return &GitHubActionsPusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		doer:     doer,
		owner:    cfg.Owner,
		repo:     cfg.Repo,
		token:    secrettext.Clone(cfg.Token),
	}, nil
}

func (p *GitHubActionsPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := json.Marshal(map[string]string{
		"encoded_value": base64.StdEncoding.EncodeToString(value),
		"key_id":        "trstctl-fixture",
	})
	if err != nil {
		return err
	}
	path := "/repos/" + pathEscape(p.owner) + "/" + pathEscape(p.repo) + "/actions/secrets/" + pathEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(p.token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", p.token))
	}
	return expect2xx(p.doer, req)
}

// AWSSecretsManagerConfig configures an AWS Secrets Manager sync destination.
type AWSSecretsManagerConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
}

type AWSSecretsManagerPusher struct {
	endpoint     string
	host         string
	doer         HTTPDoer
	region       string
	accessKeyID  string
	secretKey    []byte
	sessionToken []byte
	now          func() time.Time
}

func NewAWSSecretsManagerPusher(cfg AWSSecretsManagerConfig) (*AWSSecretsManagerPusher, error) {
	if cfg.Endpoint == "" || cfg.Region == "" || cfg.AccessKeyID == "" || len(cfg.SecretAccessKey) == 0 {
		return nil, errors.New("secretsync: aws endpoint, region, access key id, and secret access key are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	p := &AWSSecretsManagerPusher{
		endpoint:     strings.TrimRight(cfg.Endpoint, "/"),
		doer:         doer,
		region:       cfg.Region,
		accessKeyID:  cfg.AccessKeyID,
		secretKey:    secrettext.Clone(cfg.SecretAccessKey),
		sessionToken: secrettext.Clone(cfg.SessionToken),
		now:          time.Now,
	}
	if u, err := url.Parse(cfg.Endpoint); err == nil {
		p.host = u.Host
	}
	return p, nil
}

func (p *AWSSecretsManagerPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := json.Marshal(map[string]string{
		"Name":         key,
		"SecretBinary": base64.StdEncoding.EncodeToString(value),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.PutSecretValue")
	p.signV4(req, body, p.now().UTC())
	return expect2xx(p.doer, req)
}

func (p *AWSSecretsManagerPusher) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if len(p.sessionToken) > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(p.sessionToken))
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if len(p.sessionToken) > 0 {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = p.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"",
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + p.region + "/secretsmanager/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	kSigning := awsSyncSigningKey(p.secretKey, dateStamp, p.region, "secretsmanager")
	defer secret.Wipe(kSigning)
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+p.accessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}

func awsSyncSigningKey(secretAccessKey []byte, dateStamp, region, service string) []byte {
	seed := make([]byte, 0, len("AWS4")+len(secretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, secretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	return kSigning
}

// KubernetesConfig configures a Kubernetes Secret sync destination.
type KubernetesConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	Namespace   string
	BearerToken []byte
}

type KubernetesPusher struct {
	endpoint  string
	doer      HTTPDoer
	namespace string
	token     []byte
}

func NewKubernetesPusher(cfg KubernetesConfig) (*KubernetesPusher, error) {
	if cfg.Endpoint == "" || cfg.Namespace == "" {
		return nil, errors.New("secretsync: kubernetes endpoint and namespace are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	return &KubernetesPusher{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"), doer: doer, namespace: cfg.Namespace, token: secrettext.Clone(cfg.BearerToken),
	}, nil
}

func (p *KubernetesPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]string{
			"name":      key,
			"namespace": p.namespace,
		},
		"type": "Opaque",
		"data": map[string]string{"value": base64.StdEncoding.EncodeToString(value)},
	})
	if err != nil {
		return err
	}
	path := "/api/v1/namespaces/" + pathEscape(p.namespace) + "/secrets/" + pathEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(p.token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", p.token))
	}
	return expect2xx(p.doer, req)
}

type JSONPusherConfig struct {
	Endpoint    string
	HTTPClient  HTTPDoer
	BearerToken []byte
	Provider    string
}

type JSONPusher struct {
	endpoint string
	doer     HTTPDoer
	token    []byte
	provider string
}

func NewJSONPusher(cfg JSONPusherConfig) (*JSONPusher, error) {
	if cfg.Endpoint == "" || cfg.Provider == "" {
		return nil, errors.New("secretsync: json pusher endpoint and provider are required")
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	return &JSONPusher{endpoint: strings.TrimRight(cfg.Endpoint, "/"), doer: doer, token: secrettext.Clone(cfg.BearerToken), provider: cfg.Provider}, nil
}

func (p *JSONPusher) Push(ctx context.Context, key string, value []byte) error {
	body, err := json.Marshal(map[string]string{
		"provider":      p.provider,
		"key":           key,
		"encoded_value": base64.StdEncoding.EncodeToString(value),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/secrets", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(p.token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", p.token))
	}
	return expect2xx(p.doer, req)
}

func expect2xx(doer HTTPDoer, req *http.Request) error {
	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, cloudhttp.MaxBodyBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("secretsync: %s %s returned %d: %s", req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func pathEscape(v string) string { return url.PathEscape(v) }
