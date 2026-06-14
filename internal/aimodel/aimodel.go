// Package aimodel is the pluggable AI model adapter (F76, S19b.1): trustctl's AI
// reasoning runs against a cloud model OR a local (Ollama/vLLM) model by config
// alone — essential for air-gapped / sovereign PKI buyers who cannot send
// credential data to a cloud LLM. A Redactor strips key/secret material at the
// boundary before any prompt reaches a model (AN-8), and the system degrades
// gracefully when no model is configured (everything else in trustctl still works).
package aimodel

import (
	"context"
	"errors"
	"regexp"
)

// Model is a model provider. Cloud and local providers both implement it, so the
// reasoning call is identical across deployments.
type Model interface {
	Name() string
	Complete(ctx context.Context, prompt string) (string, error)
}

// Redactor removes sensitive material from a prompt before it reaches a model.
type Redactor func(prompt string) string

// ErrNoModel is returned when reasoning is attempted with no model configured.
var ErrNoModel = errors.New("aimodel: no model configured (AI features disabled)")

// Adapter wraps a Model with boundary redaction and graceful degradation.
type Adapter struct {
	model  Model
	redact Redactor
}

// New constructs an Adapter. A nil model disables AI (Available reports false);
// a nil redactor uses DefaultRedactor.
func New(model Model, redact Redactor) *Adapter {
	if redact == nil {
		redact = DefaultRedactor
	}
	return &Adapter{model: model, redact: redact}
}

// Available reports whether a model is configured.
func (a *Adapter) Available() bool { return a.model != nil }

// ModelName returns the configured model's name, or "" if none.
func (a *Adapter) ModelName() string {
	if a.model == nil {
		return ""
	}
	return a.model.Name()
}

// Reason redacts the prompt and sends it to the model. With no model configured it
// returns ErrNoModel (callers degrade gracefully). The redacted prompt is what
// crosses the boundary, so no key material reaches the model or its logs.
func (a *Adapter) Reason(ctx context.Context, prompt string) (string, error) {
	if a.model == nil {
		return "", ErrNoModel
	}
	return a.model.Complete(ctx, a.redact(prompt))
}

// Redact exposes the boundary redaction (for callers that build prompts elsewhere).
func (a *Adapter) Redact(prompt string) string { return a.redact(prompt) }

var (
	pemBlock   = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)
	secretKV   = regexp.MustCompile(`(?i)(password|secret|api[_-]?key|token)\s*[=:]\s*\S+`)
	longBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
)

// DefaultRedactor strips PEM blocks, password/secret/token assignments, and long
// base64 runs (likely key material) from a prompt, replacing them with [REDACTED].
func DefaultRedactor(prompt string) string {
	out := pemBlock.ReplaceAllString(prompt, "[REDACTED-PEM]")
	out = secretKV.ReplaceAllString(out, "[REDACTED-SECRET]")
	out = longBase64.ReplaceAllString(out, "[REDACTED]")
	return out
}

// CloudModel and LocalModel are reference providers over a Completer seam (an HTTP
// client to a cloud API or a local Ollama/vLLM endpoint). The seam keeps them
// testable; live endpoints are exercised on the CI backstop.

// Completer performs one model completion (the HTTP call seam).
type Completer interface {
	Do(ctx context.Context, prompt string) (string, error)
}

// CloudModel is a cloud-hosted model provider.
type CloudModel struct {
	Provider string
	Client   Completer
}

// Name implements Model.
func (m CloudModel) Name() string { return "cloud:" + m.Provider }

// Complete implements Model.
func (m CloudModel) Complete(ctx context.Context, prompt string) (string, error) {
	return m.Client.Do(ctx, prompt)
}

// LocalModel is a local (Ollama/vLLM) model provider for air-gapped deployments.
type LocalModel struct {
	Runtime string // "ollama" | "vllm"
	Client  Completer
}

// Name implements Model.
func (m LocalModel) Name() string { return "local:" + m.Runtime }

// Complete implements Model.
func (m LocalModel) Complete(ctx context.Context, prompt string) (string, error) {
	return m.Client.Do(ctx, prompt)
}
