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

// Fingerprint represents a certificate fingerprint in the manifest format.
type Fingerprint struct {
	Type  string `json:"type"`
	Value string `json:"value"` // colon-separated hex, e.g. "92:5E:D1:..."
}

// RelatedApplication represents an entry in the related_applications array,
// following the Web App Manifest syntax.
type RelatedApplication struct {
	Platform     string        `json:"platform,omitempty"`
	ID           string        `json:"id"`
	MinVersion   string        `json:"min_version,omitempty"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

// AttestationManifest is the top-level JSON config following Web App Manifest syntax.
type AttestationManifest struct {
	RelatedApplications []RelatedApplication `json:"related_applications"`
}

// AttestationConfig holds the configuration for x5c/device attestation validation.
type AttestationConfig struct {
	RootCAs  *x509.CertPool
	Manifest AttestationManifest
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

// loadAttestationManifest loads the attestation manifest from either a
// JSON file path or an inline JSON string (env var value).
func loadAttestationManifest(pathOrJSON string) (AttestationManifest, error) {
	var data []byte
	if strings.HasPrefix(strings.TrimSpace(pathOrJSON), "{") {
		// Treat as inline JSON
		data = []byte(pathOrJSON)
	} else {
		// Treat as file path
		var err error
		data, err = os.ReadFile(pathOrJSON)
		if err != nil {
			return AttestationManifest{}, fmt.Errorf("failed to read attestation manifest file %s: %w", pathOrJSON, err)
		}
	}
	var manifest AttestationManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return AttestationManifest{}, fmt.Errorf("failed to parse attestation manifest JSON: %w", err)
	}
	if len(manifest.RelatedApplications) == 0 {
		return AttestationManifest{}, fmt.Errorf("attestation manifest contains no related_applications")
	}
	return manifest, nil
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
		if err := validateAttestationExtension(ll, leaf, config.Manifest); err != nil {
			return nil, fmt.Errorf("attestation extension validation failed: %w", err)
		}

		return leaf.PublicKey, nil
	}
}

// validateAttestationExtension checks the Android key attestation extension on
// the leaf certificate and verifies the package name and signature digest
// against the manifest allow list.
func validateAttestationExtension(ll logger.Logger, cert *x509.Certificate, manifest AttestationManifest) error {
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

	// Check each package info against the manifest allow list
	for _, pkg := range appID.PackageInfos {
		for _, digest := range appID.SignatureDigests {
			digestColonHex := colonHex(digest)
			if isAppAllowed(pkg.PackageName, pkg.Version, digestColonHex, manifest.RelatedApplications) {
				ll.Debugw("Attestation package/signature matched",
					"packageName", pkg.PackageName,
					"signatureDigest", digestColonHex,
				)
				return nil
			}
		}
	}

	return fmt.Errorf("no matching package/signature found in allow list")
}

// colonHex formats a byte slice as colon-separated uppercase hex (e.g. "92:5E:D1:...").
func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func isAppAllowed(packageName string, version int, digestColonHex string, apps []RelatedApplication) bool {
	for _, app := range apps {
		if app.ID != packageName {
			continue
		}
		if app.MinVersion != "" {
			minVer := 0
			fmt.Sscanf(app.MinVersion, "%d", &minVer)
			if version < minVer {
				continue
			}
		}
		for _, fp := range app.Fingerprints {
			if fp.Type != "sha256_cert" {
				continue
			}
			if strings.EqualFold(fp.Value, digestColonHex) {
				return true
			}
		}
	}
	return false
}