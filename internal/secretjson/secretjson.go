// Package secretjson contains JSON marshal helpers for edge payloads that must
// carry secret bytes as wire strings without first materializing those bytes as
// Go strings.
package secretjson

import "encoding/base64"

// StringBytes marshals src as a JSON string, escaping the source bytes directly.
// It is intended for PEM/API fields whose wire schema is a string while trstctl's
// in-memory custody stays in []byte (AN-8).
type StringBytes []byte

// MarshalJSON implements json.Marshaler without converting the secret bytes to a
// string.
func (b StringBytes) MarshalJSON() ([]byte, error) {
	return QuoteBytes(b), nil
}

// Base64Bytes marshals src as a base64-encoded JSON string without constructing a
// Go string copy of either the source or encoded value.
type Base64Bytes []byte

// MarshalJSON implements json.Marshaler without using EncodeToString.
func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	return QuoteBase64(b), nil
}

// QuoteBytes returns src quoted as a JSON string. PEM and base64 connector
// payloads are ASCII; bytes outside the JSON control range are copied as-is.
func QuoteBytes(src []byte) []byte {
	out := make([]byte, 0, len(src)+2)
	return appendQuoted(out, src)
}

// QuoteBase64 returns base64(src) quoted as a JSON string.
func QuoteBase64(src []byte) []byte {
	encLen := base64.StdEncoding.EncodedLen(len(src))
	out := make([]byte, 0, encLen+2)
	out = append(out, '"')
	start := len(out)
	out = append(out, make([]byte, encLen)...)
	base64.StdEncoding.Encode(out[start:start+encLen], src)
	out = append(out, '"')
	return out
}

func appendQuoted(dst, src []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for _, c := range src {
		switch c {
		case '\\', '"':
			dst = append(dst, '\\', c)
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
			} else {
				dst = append(dst, c)
			}
		}
	}
	dst = append(dst, '"')
	return dst
}
