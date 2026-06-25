package signing

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// maxDigestLen bounds an accepted digest (SHA-512 is 64 bytes).
const maxDigestLen = 64

func algorithmFromProto(a signerpb.Algorithm) (crypto.Algorithm, error) {
	switch a {
	case signerpb.Algorithm_ALGORITHM_RSA_2048:
		return crypto.RSA2048, nil
	case signerpb.Algorithm_ALGORITHM_RSA_3072:
		return crypto.RSA3072, nil
	case signerpb.Algorithm_ALGORITHM_RSA_4096:
		return crypto.RSA4096, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P256:
		return crypto.ECDSAP256, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P384:
		return crypto.ECDSAP384, nil
	case signerpb.Algorithm_ALGORITHM_ECDSA_P521:
		return crypto.ECDSAP521, nil
	case signerpb.Algorithm_ALGORITHM_ML_DSA_44:
		return crypto.MLDSA44, nil
	case signerpb.Algorithm_ALGORITHM_ML_DSA_65:
		return crypto.MLDSA65, nil
	case signerpb.Algorithm_ALGORITHM_ML_DSA_87:
		return crypto.MLDSA87, nil
	case signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_128S:
		return crypto.SLHDSA128s, nil
	case signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_128F:
		return crypto.SLHDSA128f, nil
	case signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_192S:
		return crypto.SLHDSA192s, nil
	case signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_256S:
		return crypto.SLHDSA256s, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unsupported algorithm %v", a)
	}
}

func algorithmToProto(a crypto.Algorithm) signerpb.Algorithm {
	switch a {
	case crypto.RSA2048:
		return signerpb.Algorithm_ALGORITHM_RSA_2048
	case crypto.RSA3072:
		return signerpb.Algorithm_ALGORITHM_RSA_3072
	case crypto.RSA4096:
		return signerpb.Algorithm_ALGORITHM_RSA_4096
	case crypto.ECDSAP256:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P256
	case crypto.ECDSAP384:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P384
	case crypto.ECDSAP521:
		return signerpb.Algorithm_ALGORITHM_ECDSA_P521
	case crypto.MLDSA44:
		return signerpb.Algorithm_ALGORITHM_ML_DSA_44
	case crypto.MLDSA65:
		return signerpb.Algorithm_ALGORITHM_ML_DSA_65
	case crypto.MLDSA87:
		return signerpb.Algorithm_ALGORITHM_ML_DSA_87
	case crypto.SLHDSA128s:
		return signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_128S
	case crypto.SLHDSA128f:
		return signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_128F
	case crypto.SLHDSA192s:
		return signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_192S
	case crypto.SLHDSA256s:
		return signerpb.Algorithm_ALGORITHM_SLH_DSA_SHA2_256S
	default:
		return signerpb.Algorithm_ALGORITHM_UNSPECIFIED
	}
}

// hashFromProto maps a protocol hash to a crypto hash and its expected digest
// length in bytes.
func hashFromProto(h signerpb.Hash) (crypto.Hash, int, error) {
	switch h {
	case signerpb.Hash_HASH_SHA256:
		return crypto.SHA256, 32, nil
	case signerpb.Hash_HASH_SHA384:
		return crypto.SHA384, 48, nil
	case signerpb.Hash_HASH_SHA512:
		return crypto.SHA512, 64, nil
	default:
		return "", 0, status.Errorf(codes.InvalidArgument, "unsupported hash %v", h)
	}
}

func paddingFromProto(p signerpb.RSAPadding) crypto.RSAPadding {
	if p == signerpb.RSAPadding_RSA_PADDING_PSS {
		return crypto.RSAPSS
	}
	return crypto.RSAPKCS1v15
}

func hashToProto(h crypto.Hash) signerpb.Hash {
	switch h {
	case crypto.SHA384:
		return signerpb.Hash_HASH_SHA384
	case crypto.SHA512:
		return signerpb.Hash_HASH_SHA512
	default: // crypto.SHA256 and the empty default
		return signerpb.Hash_HASH_SHA256
	}
}

func paddingToProto(p crypto.RSAPadding) signerpb.RSAPadding {
	if p == crypto.RSAPSS {
		return signerpb.RSAPadding_RSA_PADDING_PSS
	}
	return signerpb.RSAPadding_RSA_PADDING_PKCS1V15
}

// validateSignRequest is the request-parser guard fuzzed by the protocol fuzz
// test. It must never panic on arbitrary input and must reject malformed
// requests with a structured error.
func validateSignRequest(req *signerpb.SignRequest) error {
	if req == nil || req.GetHandle() == nil || req.GetHandle().GetId() == "" {
		return status.Error(codes.InvalidArgument, "missing key handle")
	}
	if len(req.GetDigest()) == 0 {
		return status.Error(codes.InvalidArgument, "missing digest")
	}
	if len(req.GetDigest()) > maxDigestLen {
		return status.Errorf(codes.InvalidArgument, "digest too long: %d bytes", len(req.GetDigest()))
	}
	_, wantLen, err := hashFromProto(req.GetHash())
	if err != nil {
		return err
	}
	if len(req.GetDigest()) != wantLen {
		return status.Errorf(codes.InvalidArgument, "digest length %d does not match hash %v", len(req.GetDigest()), req.GetHash())
	}
	return nil
}
