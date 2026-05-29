//go:build windows

package certstore

import (
	"encoding/pem"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"certctl.io/certctl/internal/agent/destination"
)

// Windows is a CryptoAPI/CNG-backed certificate store. It installs certificates
// into a Windows system store (for example LocalMachine\MY) and, when a key is
// supplied, imports it into the Microsoft Software Key Storage Provider and
// links it to the certificate as a non-exportable, machine-scoped key.
//
// This file compiles only for GOOS=windows; CI verifies it builds via
// cross-compilation, and its end-to-end behavior is validated on Windows hosts.
// The platform-neutral contract it implements is exercised on every platform by
// the in-process Memory store. Certificates and keys are handled as PEM/DER
// bytes (decoded with encoding/pem), so this file imports no crypto/* (AN-3).
type Windows struct{}

// NewWindows returns a CryptoAPI-backed certificate store.
func NewWindows() *Windows { return &Windows{} }

var _ destination.CertStore = (*Windows)(nil)

const (
	x509AndPKCS7Encoding   = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING
	certFriendlyNamePropID = 11
	certKeyProvInfoPropID  = 2
	certNCryptKeySpec      = 0xFFFFFFFF
	ncryptOverwriteKeyFlag = 0x00000001
	ncryptMachineKeyFlag   = 0x00000020
	certFindAny            = 0
)

var (
	modcrypt32                            = windows.NewLazySystemDLL("crypt32.dll")
	procCertAddEncodedCertificateToStore  = modcrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertSetCertificateContextProperty = modcrypt32.NewProc("CertSetCertificateContextProperty")
	procCertGetCertificateContextProperty = modcrypt32.NewProc("CertGetCertificateContextProperty")
	procCertFreeCertificateContext        = modcrypt32.NewProc("CertFreeCertificateContext")

	modncrypt                     = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = modncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptImportKey           = modncrypt.NewProc("NCryptImportKey")
	procNCryptFreeObject          = modncrypt.NewProc("NCryptFreeObject")
)

// cryptDataBlob mirrors CRYPT_DATA_BLOB / CRYPT_INTEGER_BLOB.
type cryptDataBlob struct {
	cbData uint32
	pbData *byte
}

// cryptKeyProvInfo mirrors CRYPT_KEY_PROV_INFO: it links a certificate to the
// CNG key that backs it.
type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ProvParamN    uint32
	ProvParam     uintptr
	KeySpec       uint32
}

func locationFlag(loc destination.StoreLocation) uint32 {
	if loc == destination.CurrentUser {
		return windows.CERT_SYSTEM_STORE_CURRENT_USER
	}
	return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
}

func openSystemStore(ref destination.StoreRef) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(ref.Name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		locationFlag(ref.Location),
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		return 0, fmt.Errorf("certstore: open %s: %w", ref, err)
	}
	return h, nil
}

func decodeOne(pemBytes []byte, want string) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("certstore: no PEM %s block", want)
	}
	return block.Bytes, nil
}

func addEncoded(store windows.Handle, der []byte) (*windows.CertContext, error) {
	var ctx *windows.CertContext
	r, _, e := procCertAddEncodedCertificateToStore.Call(
		uintptr(store),
		uintptr(x509AndPKCS7Encoding),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		uintptr(windows.CERT_STORE_ADD_REPLACE_EXISTING),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if r == 0 {
		return nil, fmt.Errorf("certstore: CertAddEncodedCertificateToStore: %w", e)
	}
	return ctx, nil
}

func setFriendlyName(ctx *windows.CertContext, name string) error {
	w, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	blob := cryptDataBlob{cbData: uint32(len(w) * 2), pbData: (*byte)(unsafe.Pointer(&w[0]))}
	r, _, e := procCertSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		uintptr(certFriendlyNamePropID),
		0,
		uintptr(unsafe.Pointer(&blob)),
	)
	if r == 0 {
		return fmt.Errorf("certstore: set friendly name: %w", e)
	}
	return nil
}

// AddCertificate adds a certificate to the store with no associated key.
func (w *Windows) AddCertificate(ref destination.StoreRef, friendlyName string, certPEM []byte) error {
	der, err := decodeOne(certPEM, "certificate")
	if err != nil {
		return err
	}
	store, err := openSystemStore(ref)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	ctx, err := addEncoded(store, der)
	if err != nil {
		return err
	}
	defer procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
	return setFriendlyName(ctx, friendlyName)
}

// ImportWithKey adds the certificate and links its private key, imported
// non-exportable into the Microsoft Software Key Storage Provider.
func (w *Windows) ImportWithKey(ref destination.StoreRef, friendlyName string, certPEM, keyPEM []byte) error {
	der, err := decodeOne(certPEM, "certificate")
	if err != nil {
		return err
	}
	store, err := openSystemStore(ref)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	ctx, err := addEncoded(store, der)
	if err != nil {
		return err
	}
	defer procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
	if err := setFriendlyName(ctx, friendlyName); err != nil {
		return err
	}
	return importAndLinkKey(ctx, keyPEM, ref.Location == destination.LocalMachine)
}

// importAndLinkKey imports the PEM private key as a PKCS#8 blob into the CNG
// software KSP (so no algorithm-specific marshaling is needed) and links it to
// the certificate context via CERT_KEY_PROV_INFO.
func importAndLinkKey(ctx *windows.CertContext, keyPEM []byte, machine bool) error {
	der, err := decodeOne(keyPEM, "private key")
	if err != nil {
		return err
	}
	provName, _ := windows.UTF16PtrFromString("Microsoft Software Key Storage Provider")
	blobType, _ := windows.UTF16PtrFromString("PKCS8_PRIVATEKEY")

	var prov uintptr
	if st, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&prov)),
		uintptr(unsafe.Pointer(provName)),
		0,
	); st != 0 {
		return fmt.Errorf("certstore: NCryptOpenStorageProvider: status 0x%x", st)
	}
	defer procNCryptFreeObject.Call(prov)

	flags := uintptr(ncryptOverwriteKeyFlag)
	if machine {
		flags |= ncryptMachineKeyFlag
	}
	var key uintptr
	if st, _, _ := procNCryptImportKey.Call(
		prov,
		0,
		uintptr(unsafe.Pointer(blobType)),
		0,
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		flags,
	); st != 0 {
		return fmt.Errorf("certstore: NCryptImportKey: status 0x%x", st)
	}
	defer procNCryptFreeObject.Call(key)

	info := cryptKeyProvInfo{ProvName: provName, KeySpec: certNCryptKeySpec}
	if r, _, e := procCertSetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		uintptr(certKeyProvInfoPropID),
		0,
		uintptr(unsafe.Pointer(&info)),
	); r == 0 {
		return fmt.Errorf("certstore: link key to certificate: %w", e)
	}
	return nil
}

// Find returns the certificate stored under (ref, friendlyName) by enumerating
// the store and matching the friendly-name property.
func (w *Windows) Find(ref destination.StoreRef, friendlyName string) (destination.Entry, bool, error) {
	store, err := openSystemStore(ref)
	if err != nil {
		return destination.Entry{}, false, err
	}
	defer windows.CertCloseStore(store, 0)

	// Enumerate via the typed x/sys wrapper (CERT_FIND_ANY), which returns a
	// *CertContext directly — avoiding any uintptr-to-pointer conversion.
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertFindCertificateInStore(store, x509AndPKCS7Encoding, 0, certFindAny, nil, prev)
		if err != nil || ctx == nil {
			return destination.Entry{}, false, nil
		}
		prev = ctx
		if friendlyNameOf(ctx) != friendlyName {
			continue
		}
		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		return destination.Entry{
			CertPEM:       certPEM,
			HasPrivateKey: propPresent(ctx, certKeyProvInfoPropID),
			Exportable:    false,
			Ref:           ref,
		}, true, nil
	}
}

func getProp(ctx *windows.CertContext, propID uint32) ([]byte, bool) {
	var n uint32
	if r, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(propID), 0, uintptr(unsafe.Pointer(&n)),
	); r == 0 || n == 0 {
		return nil, false
	}
	buf := make([]byte, n)
	if r, _, _ := procCertGetCertificateContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)), uintptr(propID), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
	); r == 0 {
		return nil, false
	}
	return buf[:n], true
}

func friendlyNameOf(ctx *windows.CertContext) string {
	b, ok := getProp(ctx, certFriendlyNamePropID)
	if !ok || len(b) < 2 {
		return ""
	}
	// The property is a little-endian UTF-16 string; decode it pair-by-pair
	// rather than reinterpreting the byte slice (which go vet flags).
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return windows.UTF16ToString(u16)
}

func propPresent(ctx *windows.CertContext, propID uint32) bool {
	_, ok := getProp(ctx, propID)
	return ok
}
