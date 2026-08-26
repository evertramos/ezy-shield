// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// Minimal AWS Signature Version 4 request signing (ADR-0012, issue #200).
// Stdlib only, by decision: the algorithm is small, frozen, and fails
// closed — a wrong signature is a 403, never a silent partial success.
// Scope is deliberately narrow: POST requests with an in-memory body to a
// single service endpoint (wafv2), which is all the AWS WAF enforcer ever
// sends. Signed headers are the fixed set the WAFv2 JSON-RPC protocol
// uses; there is no support for query signing, presigning, chunked
// uploads, or S3 quirks — growing this file beyond wafv2's needs requires
// a new ADR per ADR-0012.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// awsCredentials is one resolved credential set from the chain
// (awscreds.go). SecretAccessKey must never appear in logs or errors.
type awsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time // zero for static credentials
}

// signSigV4 signs req in place: sets X-Amz-Date (and X-Amz-Security-Token
// when the credentials carry one) and the Authorization header. body must
// be the exact request payload; now should be time.Now() outside tests.
func signSigV4(req *http.Request, body []byte, creds awsCredentials, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	payloadHash := sha256.Sum256(body)

	// Canonical headers: host plus every x-amz-* and content-type header
	// present on the request, lowercased and sorted.
	type hdr struct{ name, value string }
	canonical := []hdr{{"host", req.Host}}
	if req.Host == "" {
		canonical[0].value = req.URL.Host
	}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "content-type" || strings.HasPrefix(lower, "x-amz-") {
			canonical = append(canonical, hdr{lower, strings.TrimSpace(strings.Join(values, ","))})
		}
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].name < canonical[j].name })

	var canonicalHeaders, signedList strings.Builder
	for i, h := range canonical {
		canonicalHeaders.WriteString(h.name + ":" + h.value + "\n")
		if i > 0 {
			signedList.WriteString(";")
		}
		signedList.WriteString(h.name)
	}
	signedHeaders := signedList.String()

	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		uri,
		req.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		hex.EncodeToString(payloadHash[:]),
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hex.EncodeToString(crHash[:]),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential="+creds.AccessKeyID+"/"+scope+
			", SignedHeaders="+signedHeaders+
			", Signature="+signature)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
