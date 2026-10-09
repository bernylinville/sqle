// Package secretkey provides domain-separated key derivation from the DMS
// root secret (config items dms.secret_key / sqle.secret_key).
//
// Signing keys for JWT and data-encryption keys for AES are never used
// directly as configured. Each usage domain derives its own 32-byte key from
// the root secret with HKDF-SHA256 (Go standard library crypto/hkdf) under a
// fixed, distinct info domain, so compromise of one derived key does not
// expose the other domain, and the root secret length is not constrained by
// the AES block-cipher key sizes (16/24/32 bytes).
//
// Hardening for CVE-2025-15107 / GHSA-43h9-hc38-qph5: binaries must refuse to
// start when the root secret is missing or weak; see Validate. There is no
// code path that silently falls back to known default keys.
//
// This package is the single shared implementation for both the dms repo
// (pkg/dms-common) and the sqle repo (vendor copy of dms-common). The two
// copies must stay byte-identical in behaviour; cross-repo derivation
// consistency is locked by unit tests (see sqle-jwt-secret-fix task 03).
package secretkey

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// HKDF info domains, fixed per usage. Changing any value changes every
// derived key and thereby invalidates all existing JWT tokens and AES
// ciphertexts of that domain.
const (
	InfoJWT = "actiontech-dms/jwt/v1"
	InfoAES = "actiontech-dms/aes/v1"
)

// DerivedKeyLength is the length in bytes of every derived key.
const DerivedKeyLength = 32

// MinRootSecretLength is the minimum length in bytes the root secret must
// have for a binary to be allowed to start.
const MinRootSecretLength = 32

// DeriveKey derives a 32-byte key for the given usage domain (InfoJWT,
// InfoAES) from the root secret using HKDF-SHA256 (RFC 5869) with no salt
// and the fixed info domain.
func DeriveKey(rootSecret string, info string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, []byte(rootSecret), nil, info, DerivedKeyLength)
	if err != nil {
		return nil, fmt.Errorf("derive key for domain %q: %w", info, err)
	}
	return key, nil
}

// Validate reports whether the root secret is strong enough to start with.
// An empty or too short secret must make callers refuse to start instead of
// silently running on known default keys (CVE-2025-15107).
func Validate(rootSecret string) error {
	if len(rootSecret) < MinRootSecretLength {
		return fmt.Errorf("secret_key is empty or shorter than %d bytes (got %d bytes)", MinRootSecretLength, len(rootSecret))
	}
	return nil
}
