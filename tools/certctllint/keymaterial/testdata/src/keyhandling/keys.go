//certctl:keymaterial
package keyhandling

// This package handles key material, so string-typed fields, parameters, and
// results are forbidden (AN-8); []byte must be used instead.

type PrivateKey struct {
	Bytes []byte
	PEM   string // want "must not use string for key material"
}

func Sign(priv string) {} // want "must not use string for key material"

func Export() (pem string) { // want "must not use string for key material"
	return ""
}
