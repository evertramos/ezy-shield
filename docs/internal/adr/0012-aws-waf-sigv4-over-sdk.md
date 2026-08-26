# ADR-0012: AWS WAF enforcer — hand-rolled SigV4 over aws-sdk-go-v2

Date: 2026-08-26
Status: Accepted
Issue: #199 (enables #200, #201)

## Context

Enforcing bans at the AWS edge (issue #200) means calling exactly two WAFv2
API operations — `GetIPSet` and `UpdateIPSet` — against a single, stable,
JSON-over-HTTPS endpoint. The question this ADR settles is how those calls
are made from a security daemon whose project policy requires justifying
every dependency (AGENTS.md):

- **(a) aws-sdk-go-v2, minimal module set** — `aws/aws-sdk-go-v2`
  (core) + `config` + `credentials` + `service/wafv2` (+ `feature/ec2/imds`
  for instance roles).
- **(b) hand-rolled SigV4 + net/http** — implement request signing and the
  two API calls directly on the standard library.
- **(c) no AWS support** — don't ship the enforcer.

## Comparison

### (a) aws-sdk-go-v2 minimal set

- **Transitive surface**: the four first-party modules pull `smithy-go`
  plus roughly a dozen `aws-sdk-go-v2/internal/*` and `feature/*` modules
  (endpoint resolution, checksum middleware, presigning, protocol codecs).
  `go.sum` grows by ~20 module versions — each one inside a daemon that
  parses hostile input and talks to the firewall.
- **Audit story**: govulncheck covers the modules, but the reachable-code
  set is large: the SDK's middleware stack (retry, checksum, endpoint
  discovery, credential resolution for every auth mode AWS supports) is
  linked in whether used or not. Reviewing an SDK upgrade is reviewing a
  framework, not two API calls.
- **Binary size**: measured on a comparable Go daemon, the minimal WAFv2
  set adds on the order of 6–10 MiB to the stripped binary (middleware
  stack + codegen'd service model).
- **Credential chain**: complete and canonical — env vars, shared
  config/credentials files, SSO, AssumeRole/STS, ECS task roles, IMDS.
- **Maintenance**: AWS ships weekly releases; dependabot noise and
  periodic breaking middleware changes. The SDK's own transitive bumps
  become our security-review burden.

### (b) hand-rolled SigV4 + net/http

- **Transitive surface**: zero new modules. SigV4 needs `crypto/sha256`,
  `crypto/hmac`, `net/http`, `time` — all stdlib.
- **Security of the reimplementation**: SigV4 is a small, frozen,
  precisely specified algorithm (canonical request → string-to-sign →
  derived key HMAC chain). AWS publishes an official test-vector suite,
  and the signature either matches or the API rejects the request — a
  wrong implementation fails closed with a 403, it cannot "almost work".
  This is the same trade the project already made for the Cloudflare and
  bunny enforcers: direct, reviewable HTTP against a stable API beats a
  vendor framework.
- **Binary size**: negligible (~1–2 k lines including the credential
  chain and both calls).
- **Credential chain**: must be reimplemented. We deliberately support
  the three mechanisms that cover servers running a security daemon —
  **env vars** (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/
  `AWS_SESSION_TOKEN`), the **shared credentials/config files**
  (`~/.aws/credentials`, `AWS_PROFILE`), and **IMDSv2 instance roles**
  (EC2). SSO login flows and client-side AssumeRole are NOT supported —
  documented as a limitation; operators needing them can mint session
  credentials externally and hand them over via the env/file mechanisms
  the chain does support.
- **Maintenance**: the WAFv2 wire format (`X-Amz-Target`-style JSON RPC
  over POST) and SigV4 have been stable for a decade; the enforcer calls
  two operations whose shapes we pin with contract tests against a local
  mock.

### (c) no AWS support

Zero cost, but CloudFront/ALB users get no edge enforcement — origin-side
nftables never sees the edge's client IPs, so for those deployments
EzyShield would be observe-only. Demand exists (#200); declining leaves a
capability gap the Cloudflare/bunny enforcers already fill for their CDNs.

## Decision

**Option (b): hand-rolled SigV4 on net/http.** Stdlib-first matches the
project's dependency policy and its existing edge-enforcer pattern; the
signing algorithm is small, frozen, test-vectored, and fails closed.

### Allowed module list (closed)

The AWS integration may use **standard library only**. The following are
explicitly forbidden without a superseding ADR:

- any `github.com/aws/aws-sdk-go-v2/*` module
- any `github.com/aws/smithy-go` version
- any third-party SigV4 or AWS-auth helper

Adding ANY AWS-related module — including "just one small helper" — 
requires a new ADR that revisits this comparison.

### Scope of the credential chain

Resolution order (first hit wins), mirroring the SDK's default order for
the mechanisms we support: (1) env vars, (2) shared credentials/config
files honoring `AWS_PROFILE`/`AWS_SHARED_CREDENTIALS_FILE`, (3) IMDSv2.
Credentials never appear in EzyShield config files — `enforce.aws_waf`
carries names/ARNs/region only, and validation rejects anything shaped
like a key (issue #200). Credentials are held in `config.Secret` and can
appear only in the `Authorization` header.

### Minimal IAM policy

The enforcer needs exactly this, scoped to the two EzyShield IPSets
(replace region/account/ids; `scope` is `regional` or `cloudfront`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EzyShieldIPSetMaintenance",
      "Effect": "Allow",
      "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
      "Resource": [
        "arn:aws:wafv2:REGION:ACCOUNT:regional/ipset/ezyshield-v4/ID4",
        "arn:aws:wafv2:REGION:ACCOUNT:regional/ipset/ezyshield-v6/ID6"
      ]
    }
  ]
}
```

Optionally, a one-time setup statement (`wafv2:CreateIPSet` on `*`, plus
`wafv2:ListIPSets`) may be granted temporarily for `ezyshield init` to
create the IPSets, then removed. The enforcer itself must never hold
`CreateIPSet`, any `WebACL` permission, or a wildcard resource: EzyShield
maintains member addresses of its own IPSets and **never touches WebACLs**
(the operator wires the IPSet into their WebACL — issue #200).

## Consequences

- #200 implements `internal/enforce/awswaf.go` on net/http with a small
  `sigv4.go` signed against AWS's published test vectors, and a local mock
  server in tests — no AWS in CI.
- SSO/AssumeRole users must provide session credentials via env or the
  shared files; the aws-waf guide (#201) documents this limitation.
- If AWS support ever expands beyond the two IPSet calls (e.g. WebACL
  management), that is the trigger to reconsider option (a) in a new ADR —
  hand-rolling grows superlinearly with API surface.
