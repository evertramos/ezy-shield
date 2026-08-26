// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// AWS credential chain for the WAF enforcer (ADR-0012, issue #200).
// Deliberately narrow: env vars → shared credentials/config files → IMDSv2.
// SSO and client-side AssumeRole are out of scope per the ADR; operators
// using them mint session credentials externally and pass them via the env
// or file mechanisms. Credentials NEVER come from EzyShield config files.
//
// Secret discipline (§3): resolved secrets live only in awsCredentials
// values handed to the signer; nothing here logs or wraps a secret into an
// error message.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// awsIMDSBase is the EC2 instance-metadata service; overridable in
	// tests and via AWS_EC2_METADATA_SERVICE_ENDPOINT (the standard var).
	awsIMDSBase = "http://169.254.169.254"
	// awsCredsRefreshMargin refreshes expiring (IMDS) credentials this long
	// before their expiration so in-flight requests never race the expiry.
	awsCredsRefreshMargin = 5 * time.Minute
)

// awsCredProvider resolves credentials through the chain, caching the
// result until (near) expiry. Safe for concurrent use.
type awsCredProvider struct {
	client   *http.Client
	imdsBase string

	mu    sync.Mutex
	cred  awsCredentials
	valid bool
}

func newAWSCredProvider() *awsCredProvider {
	base := os.Getenv("AWS_EC2_METADATA_SERVICE_ENDPOINT")
	if base == "" {
		base = awsIMDSBase
	}
	return &awsCredProvider{
		client:   &http.Client{Timeout: 2 * time.Second},
		imdsBase: strings.TrimSuffix(base, "/"),
	}
}

// credentials returns a currently-valid credential set, resolving the
// chain on first use and again when a set with an expiry nears it.
func (p *awsCredProvider) credentials(ctx context.Context) (awsCredentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.valid && (p.cred.Expiration.IsZero() || time.Until(p.cred.Expiration) > awsCredsRefreshMargin) {
		return p.cred, nil
	}
	cred, err := p.resolve(ctx)
	if err != nil {
		return awsCredentials{}, err
	}
	p.cred, p.valid = cred, true
	return cred, nil
}

// resolve walks the chain: env → shared files → IMDSv2 (first hit wins,
// matching the SDK's default order for the supported mechanisms).
func (p *awsCredProvider) resolve(ctx context.Context) (awsCredentials, error) {
	if c, ok := credsFromEnv(); ok {
		return c, nil
	}
	if c, ok, err := credsFromSharedFile(); err != nil {
		return awsCredentials{}, err
	} else if ok {
		return c, nil
	}
	if c, err := p.credsFromIMDS(ctx); err == nil {
		return c, nil
	} else {
		return awsCredentials{}, fmt.Errorf(
			"enforce/awswaf: no AWS credentials found (checked env vars, shared credentials file, IMDSv2): %w", err)
	}
}

func credsFromEnv() (awsCredentials, bool) {
	id := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if id == "" || secret == "" {
		return awsCredentials{}, false
	}
	return awsCredentials{
		AccessKeyID:     id,
		SecretAccessKey: secret,
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
	}, true
}

// credsFromSharedFile reads the AWS shared credentials file (INI), honoring
// AWS_SHARED_CREDENTIALS_FILE and AWS_PROFILE. A missing file is a clean
// miss; a present-but-unreadable file is an error worth surfacing.
func credsFromSharedFile() (awsCredentials, bool, error) {
	path := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return awsCredentials{}, false, nil
		}
		path = filepath.Join(home, ".aws", "credentials")
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-owned credentials file location per AWS convention
	if err != nil {
		if os.IsNotExist(err) {
			return awsCredentials{}, false, nil
		}
		return awsCredentials{}, false, fmt.Errorf("enforce/awswaf: read shared credentials file: %w", err)
	}

	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "default"
	}

	var cred awsCredentials
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != profile {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		switch key {
		case "aws_access_key_id":
			cred.AccessKeyID = value
		case "aws_secret_access_key":
			cred.SecretAccessKey = value
		case "aws_session_token":
			cred.SessionToken = value
		}
	}
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return awsCredentials{}, false, nil
	}
	return cred, true, nil
}

// credsFromIMDS fetches instance-role credentials via IMDSv2 (token-based;
// IMDSv1 fallback is deliberately not implemented).
func (p *awsCredProvider) credsFromIMDS(ctx context.Context) (awsCredentials, error) {
	token, err := p.imdsPut(ctx, "/latest/api/token")
	if err != nil {
		return awsCredentials{}, fmt.Errorf("IMDSv2 token: %w", err)
	}
	role, err := p.imdsGet(ctx, "/latest/meta-data/iam/security-credentials/", token)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("IMDS role name: %w", err)
	}
	role = strings.TrimSpace(strings.Split(role, "\n")[0])
	if role == "" {
		return awsCredentials{}, fmt.Errorf("IMDS: no IAM role attached")
	}
	body, err := p.imdsGet(ctx, "/latest/meta-data/iam/security-credentials/"+role, token)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("IMDS role credentials: %w", err)
	}
	var doc struct {
		Code            string
		AccessKeyId     string //nolint:revive,staticcheck // field names match the IMDS document
		SecretAccessKey string
		Token           string
		Expiration      time.Time
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return awsCredentials{}, fmt.Errorf("IMDS credentials document: %w", err)
	}
	if doc.Code != "Success" || doc.AccessKeyId == "" {
		return awsCredentials{}, fmt.Errorf("IMDS credentials document: code %q", doc.Code)
	}
	return awsCredentials{
		AccessKeyID:     doc.AccessKeyId,
		SecretAccessKey: doc.SecretAccessKey,
		SessionToken:    doc.Token,
		Expiration:      doc.Expiration,
	}, nil
}

func (p *awsCredProvider) imdsPut(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.imdsBase+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	return p.imdsDo(req)
}

func (p *awsCredProvider) imdsGet(ctx context.Context, path, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.imdsBase+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	return p.imdsDo(req)
}

func (p *awsCredProvider) imdsDo(req *http.Request) (string, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(body), nil
}
