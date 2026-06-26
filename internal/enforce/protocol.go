// Package enforce implements sdk.Enforcer backed by nftables.
//
// Privilege separation: the NftablesEnforcer (this package) runs inside the
// main daemon as an unprivileged user. It communicates with the
// ezyshield-enforcer helper (CAP_NET_ADMIN) over a unix socket using
// newline-delimited JSON. The helper accepts only the fixed verb set
// {add, del, flush, list, ping} with typed, validated arguments — no raw
// nft syntax is ever passed from caller to helper.
package enforce

// Request is sent from the main daemon to the privileged enforcer helper.
// IP must be a valid netip.Addr or netip.Prefix string; raw nft syntax
// is never accepted and will be rejected by the helper.
type Request struct {
	Verb       string `json:"verb"`
	IP         string `json:"ip,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"` // 0 = permanent
}

// Response is returned by the helper for every request.
type Response struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	IPs   []string `json:"ips,omitempty"` // populated for "list" verb
}
