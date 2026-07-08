package dashboard

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
)

// csrfCtxKey is a package-private context key used to carry sessionInfo
// from requireAuth into individual handlers. Using an unexported type keeps
// callers outside this package from colliding on the string form.
type csrfCtxKey struct{}

// csrfFormField is the hidden input name every POST form must carry. Kept
// short so the wire size overhead of embedding it in every write form is
// negligible.
const csrfFormField = "csrf_token"

// sessionFromContext returns the sessionInfo attached by requireAuth. It
// returns ok=false if the middleware chain was misconfigured — which is a
// programmer error, not something a browser can trigger.
func sessionFromContext(ctx context.Context) (sessionInfo, bool) {
	info, ok := ctx.Value(csrfCtxKey{}).(sessionInfo)
	return info, ok
}

// withSession returns a shallow-copy ctx carrying info. Used by requireAuth.
func withSession(ctx context.Context, info sessionInfo) context.Context {
	return context.WithValue(ctx, csrfCtxKey{}, info)
}

// errCSRFMismatch is returned when the submitted token does not match the
// server's copy. It is compared by identity so tests can assert on it.
var errCSRFMismatch = errors.New("csrf: submitted token does not match session")

// checkCSRF validates the CSRF token on POST requests. It parses the form
// (POST bodies are small — form-encoded IPs and reasons), reads the field,
// and compares with the expected token in constant time. Failures write
// 403 to w and return non-nil error so the caller can bail without
// further work.
func checkCSRF(w http.ResponseWriter, r *http.Request, expected string) error {
	if expected == "" {
		// Programmer error: session should have been checked first.
		http.Error(w, "forbidden", http.StatusForbidden)
		return errCSRFMismatch
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	got := r.Form.Get(csrfFormField)
	if got == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return errCSRFMismatch
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return errCSRFMismatch
	}
	return nil
}
