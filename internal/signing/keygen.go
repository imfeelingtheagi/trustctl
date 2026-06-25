package signing

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/pqc"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// signerKey is the private-key handle the signer process keeps in RAM. It is a
// digest signer plus an explicit destroy hook, so classical LockedSigner,
// ML-DSA pqc.Signer, and SLHDSASigner can share the same AN-4 storage path.
type signerKey interface {
	crypto.DigestSigner
	Destroy()
}

type privateKeyBytesExporter interface {
	PrivateKeyBytes() ([]byte, error)
}

func generateSigningKey(alg crypto.Algorithm) (signerKey, error) {
	switch alg {
	case crypto.MLDSA44, crypto.MLDSA65, crypto.MLDSA87:
		return pqc.GenerateKey(alg)
	case crypto.SLHDSA128s, crypto.SLHDSA128f, crypto.SLHDSA192s, crypto.SLHDSA256s:
		return crypto.GenerateSLHDSAKey(alg)
	default:
		return crypto.GenerateLockedKey(alg)
	}
}

func signingKeyFromSealedBytes(protoAlg signerpb.Algorithm, privateKey []byte) (signerKey, error) {
	if protoAlg == signerpb.Algorithm_ALGORITHM_UNSPECIFIED {
		return crypto.LockedKeyFromPKCS8(privateKey)
	}
	alg, err := algorithmFromProto(protoAlg)
	if err != nil {
		return nil, err
	}
	switch alg {
	case crypto.MLDSA44, crypto.MLDSA65, crypto.MLDSA87:
		return pqc.NewSignerFromPrivateKey(alg, privateKey)
	case crypto.SLHDSA128s, crypto.SLHDSA128f, crypto.SLHDSA192s, crypto.SLHDSA256s:
		return crypto.NewSLHDSAKeyFromPrivateKey(alg, privateKey)
	default:
		return crypto.NewLockedSignerFromPKCS8(alg, privateKey)
	}
}

func privateKeyBytesForSealing(key signerKey) ([]byte, error) {
	if locked, ok := key.(*crypto.LockedSigner); ok {
		return locked.PKCS8()
	}
	if exporter, ok := key.(privateKeyBytesExporter); ok {
		return exporter.PrivateKeyBytes()
	}
	return nil, fmt.Errorf("signing: key type %T cannot export sealed private bytes", key)
}
