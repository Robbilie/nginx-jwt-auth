package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/robbilie/nginx-jwt-auth/logger"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/umisama/go-regexpcache"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of http requests handled",
	}, []string{"status"})
	validationTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_subrequest_auth_jwt_token_validation_time_seconds",
		Help:    "Number of seconds spent validating token",
		Buckets: prometheus.ExponentialBuckets(100*time.Nanosecond.Seconds(), 3, 6),
	})
)

func init() {
	requestsTotal.WithLabelValues("200")
	requestsTotal.WithLabelValues("401")
	requestsTotal.WithLabelValues("405")
	requestsTotal.WithLabelValues("500")

	prometheus.MustRegister(
		requestsTotal,
		validationTime,
	)
}

func main() {
	logger := logger.NewLogger(getenv("LOG_LEVEL", "info")) // "debug", "info", "warn", "error", "fatal"

	insecureSkipVerify := getenv("INSECURE_SKIP_VERIFY", "false")
	if insecureSkipVerify == "true" {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	jwksUrl := getenv("JWKS_URL", "error")
	if jwksUrl == "error" {
		logger.Fatalw("no JWKS_URL")
		return
	}

	server, err := newServer(logger, jwksUrl, getenv("COOKIE_NAME", ""))
	if err != nil {
		logger.Fatalw("Couldn't initialize server", "err", err)
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/validate", server.validate)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "OK") })

	bindAddr := ":" + getenv("PORT", "8080")

	logger.Infow("Starting server", "addr", bindAddr)
	err = http.ListenAndServe(bindAddr, nil)

	if err != nil {
		logger.Fatalw("Error running server", "err", err)
	}
}

type server struct {
	Keyfunc    jwt.Keyfunc
	Logger     logger.Logger
	CookieName string
}

func newServer(logger logger.Logger, jwksUrl string, cookieName string) (*server, error) {
	m := map[string]keyfunc.Options{}
	s := strings.Split(jwksUrl, ",")
	var kf jwt.Keyfunc
	if len(s) == 1 {
		jwks, err := keyfunc.Get(s[0], keyfunc.Options{
			RefreshInterval: time.Hour,
			RefreshErrorHandler: func(err error) {
				log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
		}
		kf = jwks.Keyfunc
	} else {
		for _, url := range s {
			m[url] = keyfunc.Options{
				RefreshInterval: time.Hour,
				RefreshErrorHandler: func(err error) {
					log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
				},
			}
		}
		jwks, err := keyfunc.GetMultiple(m, keyfunc.MultipleOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
		}
		kf = jwks.Keyfunc
	}

	return &server{
		Keyfunc:    kf,
		Logger:     logger,
		CookieName: cookieName,
	}, nil
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

func (s *server) validate(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	defer func() {
		if r := recover(); r != nil {
			s.Logger.Errorw("Recovered panic", "err", r)
			requestsTotal.WithLabelValues("500").Inc()
			w.WriteHeader(http.StatusInternalServerError)
		}
		s.Logger.Debugw("Handled validation request", "url", r.URL, "status", w.status, "method", r.Method, "userAgent", r.UserAgent())
	}()

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.Logger.Infow("Invalid method", "method", r.Method)
		requestsTotal.WithLabelValues("405").Inc()
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	claims, ok := s.validateDeviceToken(r)
	if !ok {
		requestsTotal.WithLabelValues("401").Inc()
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	requestsTotal.WithLabelValues("200").Inc()
	s.writeResponseHeaders(w, r, claims)
	w.WriteHeader(http.StatusOK)
}

func (s *server) validateDeviceToken(r *http.Request) (claims jwt.MapClaims, ok bool) {
	t := time.Now()
	defer validationTime.Observe(time.Since(t).Seconds())

	jwtB64, err := request.AuthorizationHeaderExtractor.ExtractToken(r)
	if err != nil {
		if s.CookieName == "" {
			s.Logger.Debugw("Failed to extract token from Authorization header", "err", err)
			return nil, false
		} else {
			cookie, err := r.Cookie(s.CookieName)
			if err != nil {
				s.Logger.Debugw("Failed to extract token from cookie", "err", err)
				return nil, false
			}
			jwtB64 = cookie.Value
		}
	}

	token, err := jwt.Parse(jwtB64, s.Keyfunc)

	if err != nil {
		s.Logger.Debugw("Failed to parse token", "err", err)
		return nil, false
	}
	if !token.Valid {
		s.Logger.Debugw("Invalid token", "token", token.Raw)
		return nil, false
	}
	if err := token.Claims.Valid(); err != nil {
		s.Logger.Debugw("Got invalid claims", "err", err)
		return nil, false
	}

	ok = s.queryStringClaimValidator(token.Claims.(jwt.MapClaims), r)

	if !ok {
		return nil, false
	}
	return token.Claims.(jwt.MapClaims), true
}

func (s *server) queryStringClaimValidator(claims jwt.MapClaims, r *http.Request) bool {
	validClaims := r.URL.Query()
	hasClaimsPrefixedKey := false
	for key := range validClaims {
		if strings.HasPrefix(key, "claims_") {
			hasClaimsPrefixedKey = true
		}
	}
	if len(validClaims) == 0 || !hasClaimsPrefixedKey {
		s.Logger.Warnw("No claims requirements set, rejecting", "queryParams", validClaims)
		return false
	}
	s.Logger.Debugw("Validating claims from query string", "validClaims", validClaims, "actualClaims", claims)

	for claimNameQ, validPatterns := range validClaims {
		if strings.HasPrefix(claimNameQ, "claims_") {
			claimName := strings.TrimPrefix(claimNameQ, "claims_")
			s.Logger.Debugw("CLAIM", "claim", claimName, "vv", validPatterns,
				"qd", validClaims)
			isRegExp := false
			if strings.HasPrefix(claimName, "regexp_") {
				claimName = strings.TrimPrefix(claimName, "regexp_")
				isRegExp = true
			}
			if !s.checkClaim(claimName, validPatterns, claims, isRegExp) {
				s.Logger.Debugw("Token claims did not match required values")
				return false
			}
		}
	}
	return true
}

func (s *server) checkClaim(
	claimName string, validPatterns []string, claims jwt.MapClaims, isRegExp bool,
) bool {
	claimObj := claims[claimName]

	switch claimVal := claimObj.(type) {
	case string:
		if contains(validPatterns, claimVal, isRegExp) {
			return true
		}
	case []interface{}:
		//short exit if there are restrictions on claim but no claims exist
		if len(claimVal) == 0 && len(validPatterns) > 0 {
			return false
		}
		// fill an actualClaims[] from  interface[]
		actualClaims := make([]string, len(claimVal))
		for i, e := range claimVal {
			claim := e.(string)
			actualClaims[i] = claim
		}
		for _, actualClaim := range actualClaims {
			for _, validPattern := range validPatterns {
				if contains([]string{validPattern}, actualClaim, isRegExp) {
					return true
				}
			}
		}
	default:
		fmt.Errorf("I don't know how to handle claim object %T\n", claimObj)
		return false
	}

	return false
}

func (s *server) writeResponseHeaders(
	w *statusWriter, r *http.Request, claims jwt.MapClaims,
) {

	var responseHeaders = make(map[string]string)
	parameters := r.URL.Query()
	for key, value := range parameters {
		if strings.HasPrefix(key, "headers_") {
			header := strings.TrimPrefix(key, "headers_")
			responseHeaders[header] = value[0]
		}
	}
	s.Logger.Debugw("responseHeaders", "rh", responseHeaders)
	if responseHeaders == nil {
		return
	}
	for header, claimName := range responseHeaders {
		claim, ok := claims[claimName]
		if !ok {
			continue
		}
		var toClaim []byte
		if sClaim, ok := claim.(string); ok {
			toClaim = ([]byte)(sClaim)
		} else {
			var err error
			toClaim, err = json.Marshal(claim)
			if err != nil {
				continue
			}
		}
		encClaim := string(toClaim)
		s.Logger.Debugw("add response header", "header", header, "claim", claim, "encClaim", encClaim)
		w.Header().Add(header, encClaim)
	}
}

func contains(haystack []string, needle string, isRegExp bool) bool {
	for _, validPattern := range haystack {
		if isRegExp == true {
			matched, err := regexpcache.MatchString(validPattern, needle)
			if err != nil {
				fmt.Errorf("unable to compile pattern %v to match claim %v , error %v\n", validPattern, needle, err)
			}
			if matched {
				return true
			}
		} else if validPattern == needle {
			return true
		}
	}
	return false
}
