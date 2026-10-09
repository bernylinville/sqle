package middleware

import (
	"encoding/hex"
	"testing"
	"time"

	dmsCommonV1 "github.com/actiontech/dms/pkg/dms-common/api/dms/v1"
	dmsCommonJwt "github.com/actiontech/dms/pkg/dms-common/api/jwt"
	dmsCommonSecretkey "github.com/actiontech/dms/pkg/dms-common/pkg/secretkey"
	"github.com/golang-jwt/jwt"
)

// Regression tests for CVE-2025-15107 / GHSA-43h9-hc38-qph5: tokens signed
// with the publicly known default key must never validate once a real
// secret_key is configured.

const (
	// fixed cross-repo derivation vector; the identical triple is asserted in
	// the dms fork (pkg/dms-common/pkg/secretkey test vector) and must stay
	// in sync so the sqle vendor copy cannot silently drift from the dms
	// implementation.
	vectorRoot    = "sqle-jwt-secret-fix-crossrepo-vector-0001"
	vectorJWTKey  = "7a9fb850c7f34b36751da8b5273142c34d8c18b95053dcd3ad34fa7dbad20bfc"
	vectorAESKey  = "fb06443d1eb9ba92ce6d8becc77ccaf3dfe7670d54564292f9e263a61902e6fe"
	strongRootMin = "0123456789012345678901234567890123" // exactly 32 bytes
)

func resetSigningKeyForTest(t *testing.T, rootSecret string) {
	t.Helper()
	origKey := dmsCommonV1.JwtSigningKey
	t.Cleanup(func() { dmsCommonV1.JwtSigningKey = origKey })
	if err := dmsCommonV1.ResetJWTSigningKey(rootSecret); err != nil {
		t.Fatalf("reset jwt signing key: %v", err)
	}
}

func forgeTokenWithDefaultSecret(t *testing.T, apn string) string {
	t.Helper()
	tok := jwt.New(jwt.SigningMethodHS256)
	claims := tok.Claims.(jwt.MapClaims)
	claims["apn"] = apn
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	s, err := tok.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("forge token: %v", err)
	}
	return s
}

// TestRejectDefaultSecretForgedToken signs an audit-plan token with the
// hardcoded upstream default key "secret" while the process is configured
// with a real secret_key; the parser used by ScannerVerifier must reject it.
func TestRejectDefaultSecretForgedToken(t *testing.T) {
	resetSigningKeyForTest(t, strongRootMin)

	forged := forgeTokenWithDefaultSecret(t, "plan-a")
	if _, err := dmsCommonJwt.ParseAuditPlanName(forged); err == nil {
		t.Fatal("token forged with the default key \"secret\" was accepted after reset to a real secret_key")
	}

	// positive control: a token signed with the derived key still parses
	good, err := dmsCommonJwt.GenJwtToken(
		dmsCommonJwt.WithAuditPlanName("plan-a"),
		dmsCommonJwt.WithExpiredTime(time.Hour))
	if err != nil {
		t.Fatalf("gen token: %v", err)
	}
	apn, err := dmsCommonJwt.ParseAuditPlanName(good)
	if err != nil {
		t.Fatalf("legit token rejected: %v", err)
	}
	if apn != "plan-a" {
		t.Fatalf("unexpected audit plan name %q", apn)
	}
}

// TestDeriveKeyCrossRepoVector locks the vendored dms-common secretkey
// implementation to the fixed cross-repo vector (see dms fork).
func TestDeriveKeyCrossRepoVector(t *testing.T) {
	jwtKey, err := dmsCommonSecretkey.DeriveKey(vectorRoot, dmsCommonSecretkey.InfoJWT)
	if err != nil {
		t.Fatalf("derive jwt key: %v", err)
	}
	aesKey, err := dmsCommonSecretkey.DeriveKey(vectorRoot, dmsCommonSecretkey.InfoAES)
	if err != nil {
		t.Fatalf("derive aes key: %v", err)
	}
	if got := hex.EncodeToString(jwtKey); got != vectorJWTKey {
		t.Fatalf("jwt derived key drifted from cross-repo vector: %s", got)
	}
	if got := hex.EncodeToString(aesKey); got != vectorAESKey {
		t.Fatalf("aes derived key drifted from cross-repo vector: %s", got)
	}
}
