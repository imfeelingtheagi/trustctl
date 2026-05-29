package enroll

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxBody = 1 << 20

// enrollRequest is the JSON body of an enrollment request: a base64 CSR (DER)
// and, for bootstrap, the one-time token.
type enrollRequest struct {
	Token string `json:"token,omitempty"`
	CSR   string `json:"csr"`
}

type enrollResponse struct {
	Certificate string `json:"certificate,omitempty"` // PEM chain
	Error       string `json:"error,omitempty"`
}

// Handler serves the enrollment endpoints over HTTP: POST /enroll/bootstrap
// (token + CSR) and POST /enroll/renewal (CSR). It is the transport an agent's
// HTTPEnroller talks to. Renewal is mTLS-gated in production (the agent presents
// its current certificate); that gating is the deployment's mutual-TLS server.
func Handler(a *Authority) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		req, csr, ok := decode(w, r)
		if !ok {
			return
		}
		chain, err := a.EnrollBootstrap(r.Context(), req.Token, csr)
		respond(w, chain, err)
	})
	mux.HandleFunc("POST /enroll/renewal", func(w http.ResponseWriter, r *http.Request) {
		_, csr, ok := decode(w, r)
		if !ok {
			return
		}
		chain, err := a.EnrollRenewal(r.Context(), csr)
		respond(w, chain, err)
	})
	return mux
}

func decode(w http.ResponseWriter, r *http.Request) (enrollRequest, []byte, bool) {
	var req enrollRequest
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cannot read request")
		return req, nil, false
	}
	if err := json.Unmarshal(data, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return req, nil, false
	}
	csr, err := base64.StdEncoding.DecodeString(req.CSR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "csr is not valid base64")
		return req, nil, false
	}
	return req, csr, true
}

func respond(w http.ResponseWriter, chain []byte, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrBadToken) {
			status = http.StatusForbidden
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, enrollResponse{Certificate: string(chain)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, enrollResponse{Error: msg})
}
