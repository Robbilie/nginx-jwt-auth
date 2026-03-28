package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mbreban/attestation"

	"github.com/robbilie/nginx-jwt-auth/logger"
)

// AllowedPackage represents an allowed Android package with its signature digests.
type AllowedPackage struct {
	PackageName string   `json:"packageName"`
	Signatures  []string `json:"signatures"` // hex-encoded SHA-256 digests
}

// AttestationConfig holds the configuration for x5c/device attestation validation.
type AttestationConfig struct {
	RootCAs         *x509.CertPool
	AllowedPackages []AllowedPackage
}

// loadRootCAsFromDir loads all PEM-encoded certificates from the given directory.
func loadRootCAsFromDir(dir string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read root CA directory %s: %w", dir, err)
	}
	loaded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			loaded++
		}
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no valid CA certificates found in %s", dir)
	}
	return pool, nil
}

// loadAllowedPackages loads the allowed packages configuration from either a
// JSON file path or a JSON string (env var value).
func loadAllowedPackages(pathOrJSON string) ([]AllowedPackage, error) {
	var data []byte
	if strings.HasPrefix(strings.TrimSpace(pathOrJSON), "[") {
		// Treat as inline JSON
		data = []byte(pathOrJSON)
	} else {
		// Treat as file path
		var err error
		data, err = os.ReadFile(pathOrJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to read allowed packages file %s: %w", pathOrJSON, err)
		}
	}
	var packages []AllowedPackage
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, fmt.Errorf("failed to parse allowed packages JSON: %w", err)
	}
	return packages, nil
}

// wrapKeyfuncWithX5C returns a jwt.Keyfunc that first checks for an x5c header.
// If present, it validates the certificate chain and attestation extension.
// If not present, it falls back to the provided keyfunc.
func wrapKeyfuncWithX5C(ll logger.Logger, fallback jwt.Keyfunc, config *AttestationConfig) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		x5cRaw, ok := token.Header["x5c"]
		if !ok {
			return fallback(token)
		}

		x5cArr, ok := x5cRaw.([]interface{})
		if !ok || len(x5cArr) == 0 {
			return nil, fmt.Errorf("x5c header is not a valid array")
		}

		// Parse all certificates from the x5c chain
		certs := make([]*x509.Certificate, 0, len(x5cArr))
		for i, raw := range x5cArr {
			certB64, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("x5c[%d] is not a string", i)
			}
			certDER, err := base64.StdEncoding.DecodeString(certB64)
			if err != nil {
				return nil, fmt.Errorf("x5c[%d]: failed to base64 decode: %w", i, err)
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, fmt.Errorf("x5c[%d]: failed to parse certificate: %w", i, err)
			}
			certs = append(certs, cert)
		}

		leaf := certs[0]

		// Build intermediate pool from remaining certs
		intermediates := x509.NewCertPool()
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}

		// Verify the certificate chain against the root CAs
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         config.RootCAs,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return nil, fmt.Errorf("x5c certificate chain verification failed: %w", err)
		}

		ll.Debugw("x5c certificate chain verified successfully")

		// Validate the key attestation extension
		if err := validateAttestationExtension(ll, leaf, config.AllowedPackages); err != nil {
			return nil, fmt.Errorf("attestation extension validation failed: %w", err)
		}

		return leaf.PublicKey, nil
	}
}

// validateAttestationExtension checks the Android key attestation extension on
// the leaf certificate and verifies the package name and signature digest
// against the allow list.
func validateAttestationExtension(ll logger.Logger, cert *x509.Certificate, allowed []AllowedPackage) error {
	ext := attestation.GetKeyExtension(cert)
	if ext == nil {
		return fmt.Errorf("certificate does not contain key attestation extension")
	}

	keyDesc, err := attestation.ParseExtension(ext.Value)
	if err != nil {
		return fmt.Errorf("failed to parse key attestation extension: %w", err)
	}

	// The attestation application ID is typically in softwareEnforced
	appID := keyDesc.SoftwareEnforced.AttestationApplicationId
	if appID == nil {
		return fmt.Errorf("no AttestationApplicationId found in attestation extension")
	}

	if len(appID.PackageInfos) == 0 {
		return fmt.Errorf("no package infos in AttestationApplicationId")
	}

	if len(appID.SignatureDigests) == 0 {
		return fmt.Errorf("no signature digests in AttestationApplicationId")
	}

	// Check each package info against the allow list
	for _, pkg := range appID.PackageInfos {
		for _, digest := range appID.SignatureDigests {
			digestHex := hex.EncodeToString(digest)
			if isPackageAllowed(pkg.PackageName, digestHex, allowed) {
				ll.Debugw("Attestation package/signature matched",
					"packageName", pkg.PackageName,
					"signatureDigest", digestHex,
				)
				return nil
			}
		}
	}

	return fmt.Errorf("no matching package/signature found in allow list")
}

func isPackageAllowed(packageName string, signatureHex string, allowed []AllowedPackage) bool {
	for _, ap := range allowed {
		if ap.PackageName != packageName {
			continue
		}
		for _, sig := range ap.Signatures {
			if strings.EqualFold(sig, signatureHex) {
				return true
			}
		}
	}
	return false
}