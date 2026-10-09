package sqled

import (
	"strings"
	"testing"

	"github.com/actiontech/sqle/sqle/config"
)

// Fail-safe for CVE-2025-15107 / GHSA-43h9-hc38-qph5: sqled must refuse to
// start when sqle.secret_key is missing or weak, instead of silently running
// on publicly known default JWT/AES keys.

func testOptions(secret string) *config.SqleOptions {
	opts := &config.SqleOptions{
		Service: config.SeviceOpts{},
	}
	opts.SecretKey = secret // embedded dmsCommonConf.BaseOptions
	return opts
}

func TestValidateConfigRejectsEmptySecretKey(t *testing.T) {
	opts := testOptions("")
	if err := validateConfig(opts); err == nil {
		t.Fatal("empty secret_key must abort startup")
	}
}

func TestValidateConfigRejectsShortSecretKey(t *testing.T) {
	opts := testOptions("short")
	err := validateConfig(opts)
	if err == nil {
		t.Fatal("short secret_key must abort startup")
	}
	if !strings.Contains(err.Error(), "CVE-2025-15107") {
		t.Fatalf("refusal should reference the CVE, got: %v", err)
	}
}

func TestValidateConfigAcceptsStrongSecretKey(t *testing.T) {
	opts := testOptions("0123456789012345678901234567890123") // 32 bytes
	if err := validateConfig(opts); err != nil {
		t.Fatalf("32-byte secret_key must be accepted, got: %v", err)
	}
}
