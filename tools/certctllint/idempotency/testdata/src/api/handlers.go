package api

import "net/http"

// A mutating handler must accept and honor an idempotency key (AN-5).

//certctl:mutation
func CreateBad(w http.ResponseWriter, r *http.Request) { // want "must accept and honor an idempotency key"
	_ = w
	_ = r
}

//certctl:mutation
func CreateGood(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	_ = key
	_ = w
}

// Unmarked is not annotated as a mutation, so it is ignored even though it does
// not touch an idempotency key.
func Unmarked(w http.ResponseWriter, r *http.Request) {
	_ = w
	_ = r
}
