# nginx-jwt-auth
This project implements a simple JWT validation endpoint meant to be used with NGINX's [subrequest authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/), and specifically work well with the Kubernetes [NGINX Ingress Controller](https://github.com/kubernetes/ingress-nginx) external auth annotations.

It validates a JWT token passed in the `Authorization` header against a configured public key, and further validates that the JWT contains appropriate claims.

## Based on

- https://github.com/carlpett/nginx-subrequest-auth-jwt
- https://github.com/ovidiubuligan/nginx-subrequest-auth-jwt
- https://github.com/FactFiber/devspace-nginx-auth-jwt
- https://github.com/new-paradigm-studio/nginx-jwt-auth


# Configuration

LOG_LEVEL debug/info/warn/error/fatal info

INSECURE_SKIP_VERIFY true/false false

ALLOW_NO_QUERY_REQUIREMENTS true/false false

PORT 8080

JWKS_PATH path to jwks pem

JWKS_URL one or multiple comma separated urls to jwks endpoints

COOKIE_NAME name of a cookie containing a jwt

CACERT_PATH comma-separated list of CA certificate file paths for TLS verification

## Device Attestation (x5c)

This application optionally supports validating JWTs self-signed by Android devices using hardware-backed key attestation. When a JWT contains an `x5c` header with the device attestation certificate chain, the application will:

1. Parse the certificate chain from the `x5c` header
2. Verify the chain against configured root CA certificates
3. Validate the Android key attestation extension on the leaf certificate
4. Check the attested package name and signing certificate fingerprint against an allow list
5. Use the leaf certificate's public key to verify the JWT signature

If no `x5c` header is present, validation falls back to the standard JWKS/public key flow.

### Configuration

X5C_ROOT_CA_DIR directory containing PEM-encoded root CA certificate files

ATTESTATION_MANIFEST path to a JSON manifest file, or an inline JSON string

Both environment variables must be set to enable device attestation support.

### Attestation Manifest

The manifest follows the Web App Manifest `related_applications` syntax:

```json
{
  "related_applications": [
    {
      "id": "com.example.myapp",
      "min_version": "10",
      "fingerprints": [
        {
          "type": "sha256_cert",
          "value": "92:5E:D1:AB:CF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45"
        }
      ]
    }
  ]
}
```

- `id` - the Android application package name
- `min_version` - (optional) minimum version code of the application
- `fingerprints` - list of allowed signing certificate fingerprints
  - `type` - must be `sha256_cert`
  - `value` - colon-separated uppercase hex SHA-256 digest of the signing certificate

A single package can have multiple fingerprint entries to support different signing keys (e.g. debug, release, different integrations).

### Kubernetes Deployment

Mount the root CA certificates and attestation manifest as ConfigMaps:

```yaml
env:
  - name: X5C_ROOT_CA_DIR
    value: /etc/attestation/root-cas
  - name: ATTESTATION_MANIFEST
    value: /etc/attestation/manifest.json
volumeMounts:
  - name: attestation-root-cas
    mountPath: /etc/attestation/root-cas
    readOnly: true
  - name: attestation-manifest
    mountPath: /etc/attestation/manifest.json
    subPath: manifest.json
    readOnly: true
```

### Query string
In query string mode, the allowed claims are passed via query string parameters to the /validate endpoint. For example, with `/validate?claims_group=developers&claims_group=administrators&claims_location=hq`, the token claims must **both** have a `group` claim of **either** `developers` or `administrators`, **and** a `location` claim of `hq`.

Each claim must be prefixed with `claims_`. Giving the same claim multiple time results in any value being accepted.
Claims prefixed with `claims_regexp_` can have regexes, their compiled versions are cached for performance reasons.

In this mode, in contrast to static mode, only a single set of acceptable claims can be passed at a time (but different NGINX server blocks can pass different sets).

If no claims are passed in this mode, the request will be denied.

# NGINX Ingress Controller integration
To use with the NGINX Ingress Controller, first create a deployment and a service for this endpoint. See the [kubernetes/](kubernetes/) directory for example manifests. Then on the ingress object you wish to authenticate, add this annotation for a server in static claims source mode:

```yaml
nginx.ingress.kubernetes.io/auth-url: http://token-validator.default.svc.cluster.local/validate
```

Or, in query string mode:

```yaml
nginx.ingress.kubernetes.io/auth-url: http://token-validator.default.svc.cluster.local/validate?claims_group=developers
```

Change the url to match the name of the service and namespace you chose when deploying. All requests will now have their JWTs validated before getting passed to the upstream service.

# Metrics
This endpoint exposes [Prometheus](https://prometheus.io) metrics on `/metrics`:

- `http_requests_total{status="<status>"}` number of requests handled, by status code (counter)
- `nginx_subrequest_auth_jwt_token_validation_time_seconds` number of seconds spent validating tokens (histogram)

# Response headers

To include fields from claims in response headers, use the `responseHeaders` configuration section. It should consist of a map
of response header to claim name. Headers will be included with
base64 encoding of the claim. If the actual claim is a string,
this will be directly encoded. If the claim is an array of strings,
this will first be json encoded, then base64 encoded.

Response headers can also be configured via the query. Use a query
parameter of the form `headers_foo=bar` to encode claims "bar"
in response header "foo".
