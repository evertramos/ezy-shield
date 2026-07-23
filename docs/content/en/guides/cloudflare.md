---
title: Deploying to Cloudflare
description: Block IPs at the edge with Cloudflare
order: 1
---

# Cloudflare Edge Enforcement

This guide walks you through setting up EzyShield to block malicious IPs at the Cloudflare edge using the **Lists mode** (recommended for most deployments).

## Modes Overview

EzyShield supports two Cloudflare enforcement modes:

| Feature | Lists | Rulesets |
|---------|------------------|-------------------|
| **API calls per ban** | 1 (account-level) | 1 per zone |
| **IP capacity** | 10,000 | ~200 per rule |
| **Multi-zone support** | Automatic | Per-zone rules |
| **WAF rule setup** | Auto-managed | Manual per zone |
| **Free plan** | ✅ (1 list, 10k items) | ✅ |
| **Least privilege** | ❌ (needs account-level token) | ✅ (zone-level token) |

Both modes are fully supported — pick per deployment (and, in multi-account
setups, per account). **Lists** suits most multi-zone deployments; **rulesets**
suits per-zone control, least-privilege zone tokens, or accounts whose
custom-list quota is already taken. Running one account in lists mode and
another in rulesets mode is a perfectly normal setup.

## Lists Mode Setup

### Step 1: Create Cloudflare API Token

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Go to **Account → API Tokens** (bottom left sidebar)
3. Click **Create Token** and select **Custom token**
4. Configure the token with these permissions:
   - **Account → Account Filter Lists → Edit** (required for managing the IP list)
   - For each zone you want to auto-manage WAF rules:
     - **Zone → Firewall Services → Edit** (optional; required if using `zone_ids`)
   - **Zone → Zone → Read** (optional; required only for the wizard's
     "cover **all** zones" answer, which enumerates the account's zones) —
     see the [Cloudflare permissions reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
5. Set restrictions as needed (IP allowlist, TTL, etc.)
6. Copy the token immediately — you won't see it again

### Step 2: Retrieve Account ID and Zone IDs

**Account ID:**
- Go to **Account → Workers** in the Cloudflare Dashboard
- The Account ID is displayed at the bottom left of the page (32 hex characters)

**Zone IDs (optional, for auto-WAF rule management):**
- For each domain/zone you want to protect
- Go to **Domain → Overview**
- Zone ID is on the right sidebar (32 hex characters)

### Step 3: Configure EzyShield

Save the API token as an environment variable:

```bash
export EZYSHIELD_CF_TOKEN="your_api_token_here"
```

Add to `config.yaml`:

```yaml
enforce:
  cloudflare:
    api_token: env:EZYSHIELD_CF_TOKEN
    mode: lists
    account_id: your_account_id_32_hex_chars
    # Optional: auto-manage WAF rules per zone
    zone_ids:
      - zone_id_1
      - zone_id_2
    # Optional: WAF rule action (default: "block")
    action: block  # or "challenge" / "js_challenge"
    # Optional: custom list name (default: "ezyshield_blocked")
    # list_name: ezyshield_blocked
```

### Step 4: Verify Configuration

Run the diagnostic command:

```bash
ezyshield test enforcer cloudflare
```

This command will:
- Verify the API token has correct permissions
- Test connectivity to Cloudflare
- List accessible zones
- Show the list status (created, item count, etc.)

### Zone coverage in the wizard

Both wizard entry points (`init` and `config enforcer cloudflare`) ask, in
lists mode, **which zones the block rule should cover**:

- **`all`** — the wizard enumerates every zone the token can read on the
  account (paginated) and persists that snapshot into `zone_ids`; the config
  stays explicit, and re-running the wizard picks up domains added later.
  Needs **Zone → Zone → Read**; without it the wizard degrades gracefully to
  the manual path and names the missing scope.
- **Explicit zone IDs** — exactly those zones, nothing enumerated.
- **ENTER** — manual setup (the wizard prints the rule to paste per zone).

For `all`/explicit, the wizard immediately creates-or-verifies the WAF
Custom Rule in each target zone (idempotent with the enforcer's own rule
management — re-running never duplicates) and prints a per-zone report:
`configured` / `already present` / `FAILED (HTTP xxx: reason)`, with manual
instructions for any failed zone. Partial failure never aborts: the config
is still saved and the daemon retries failed zones on every sync.

### Step 5: (Optional) Manual WAF Rule Setup

**If you did NOT configure `zone_ids`** in step 3 (or answered ENTER in the wizard), you must create the WAF Custom Rule manually for each zone:

1. Go to **Domain → Security → WAF → Custom rules**
2. Click **Create Rule**
3. Set:
   - **Field:** IP Source Address
   - **Operator:** is in list
   - **Value:** Select your `ezyshield_blocked` list
   - **Action:** Block (or your chosen action)
   - **Description:** `ezyshield-list-block`
4. Deploy the rule

If you configured `zone_ids`, this step is **automatic** — rules are created on first Sync.

## Rulesets Mode Setup

For deployments that want per-zone control or cannot use account-level tokens:

### Step 1: Create Zone-Level API Token

1. Go to **Zone → API Tokens** (in the zone dashboard)
2. Create a token with:
   - **Zone → Firewall → Edit** on each zone
3. Save the token as `EZYSHIELD_CF_TOKEN`

### Step 2: Configure EzyShield

```yaml
enforce:
  cloudflare:
    api_token: env:EZYSHIELD_CF_TOKEN
    mode: rulesets
    zone_ids:
      - zone_1
      - zone_2
    action: block  # or "challenge" / "js_challenge"
```

Each zone gets its own WAF Custom Rule with all blocked IPs. Expression size limits (~3900 bytes) mean approximately 200 IPs per rule; EzyShield auto-splits into multiple rules if needed.

## Plan limits and what EzyShield checks

Cloudflare quotas are plan-dependent, and a valid token does not guarantee a
working setup. Two limits matter here:

- **Custom Lists (lists mode):** the number of custom lists depends on your
  plan — **free accounts get a single custom list**. If that slot is already
  taken by another list, EzyShield's list cannot be created and enforcement
  can never work.
- **WAF custom rules (both modes):** rules are limited per zone per plan
  (5 on free). Lists mode needs one rule per covered zone referencing the
  list; rulesets mode writes its rules directly.

EzyShield checks feasibility at three moments so you find out immediately,
not during the first armed sync:

1. **Setup** (`init` / `config enforcer cloudflare`): after validating the
   token and its scope, the wizard **creates or adopts** the configured
   Custom List on the spot. A quota refusal aborts setup with the ways out
   (delete an unused list, upgrade the plan, or switch to rulesets mode) —
   no broken config is ever written. In rulesets mode the wizard reports how
   many WAF custom rules each zone already uses.
2. **On demand** (`test enforcer cloudflare`): re-runs the capability checks
   against your current config, including list existence, item count, and
   per-zone rule usage.
3. **Continuously** (`doctor`): verifies the token still resolves and is
   valid, the list still exists (with an item-count warning as you approach
   the 10k cap), and per-zone rule usage — catching lists deleted outside
   EzyShield and rotated or expired tokens.

## Troubleshooting

### "Permission denied" or "Insufficient permissions" errors

Check your token permissions:

```bash
# Verify token with curl (replace TOKEN with your actual token)
curl -H "Authorization: Bearer TOKEN" \
  https://api.cloudflare.com/client/v4/user/tokens/verify
```

Look for the required permissions in the response.

### List shows "unauthorized" in Cloudflare Dashboard

This is expected if your API token only has Account Filter Lists:Edit (not Zone:Firewall:Edit). The list exists and works; you just can't view it in the dashboard UI.

### WAF rules not auto-created

Verify:
1. `zone_ids` is configured in `config.yaml`
2. Your token has `Zone → Firewall Services → Edit` permission
3. Run `ezyshield test enforcer cloudflare` to check permission errors
4. Check logs: `ezyshield status` → look for Cloudflare entries

### "List at capacity" (10k items)

If you hit the 10k-item free-plan limit, you have two options:
1. Use **Rulesets mode** (no limit per rule, but ~200 per rule)
2. Upgrade to Cloudflare's paid plan for higher limits

## Multi-Account Setup

Agencies and freelancers often manage sites spread across separate Cloudflare
accounts, each with its own API token. A single EzyShield daemon handles them
all: every ban is applied to every configured account, and a failure on one
account never blocks the others.

The wizards set this up for you — both `ezyshield init` (CDN step) and
`ezyshield config enforcer cloudflare` ask **"Add another Cloudflare
account?"** after each account. Each account gets its own name, mode (lists
or rulesets — mixing is fine), validated token, and its own env var in
`.env` (`CLOUDFLARE_API_TOKEN` for a single unnamed account,
`CLOUDFLARE_API_TOKEN_<NAME>` for named ones). Re-running
`config enforcer cloudflare` lets you pick an existing account to
reconfigure or add another.

The resulting config:

```yaml
enforce:
  cloudflare:
    # Account 1
    - name: client_a
      api_token: env:CLOUDFLARE_API_TOKEN_CLIENT_A
      mode: lists
      account_id: account_a_id
      zone_ids: [zone_a1, zone_a2]
    # Account 2 — a different mode per account is fine
    - name: client_b
      api_token: env:CLOUDFLARE_API_TOKEN_CLIENT_B
      mode: rulesets
      zone_ids: [zone_b1]
```

With more than one account, every entry needs a unique `name` (the wizard
enforces this, and offers to name a pre-existing unnamed entry). Each account
gets independent list/rule management and per-account status in
`test enforcer cloudflare` and `doctor`. Logs show
`enforce/cloudflare[client_a]` and `enforce/cloudflare[client_b]` for clarity.

## Rate Limiting

EzyShield enforces a 4 requests/second rate limit on Cloudflare API calls to stay well below the public API limits. This is automatically managed and requires no configuration.

## Security Considerations

- API tokens are resolved at daemon startup and never logged
- Tokens are not included in error messages or logs
- Always use `env:VARNAME` references; inline tokens in config are rejected at load time
- Restrict token permissions and IP addresses in Cloudflare settings when possible
- The account-level token can modify your Custom IP Lists — restrict access accordingly

## Validating Your Configuration

### Using `test enforcer cloudflare`

After configuration, validate your setup with:

```bash
ezyshield test enforcer cloudflare --config-dir /etc/ezyshield/
```

This command will:
- Verify the API token is valid and active
- Check account and zone access
- Validate Cloudflare permissions for your token
- Report what works and what's missing
- Provide clear fix suggestions

**Example output (lists mode with zone_ids):**

```
Cloudflare enforcer (mode: lists): pass
────────────────────────────────────
✓ Token validity: Token ID: abc...def, status: active
✓ Account access: Account ID: 0123456789abcdef
✓ List access (read): List "ezyshield_blocked" found (147 items, ID: lstxxxxx)
✓ Zone WAF access: Zone example.com (zone_id: aaa111) — WAF rule access OK
✗ Zone WAF access: Zone shop.example.org (zone_id: ccc333) — 403 Forbidden
  └─ Ensure token has Zone:Firewall Services:Edit on this zone

Result: 4/5 checks passed, 1 failed
```

**Exit code**: 0 if all checks pass, 1 if any check fails

**JSON output**: Use `--json` flag for structured output suitable for automation

## See Also

- ADR-0002: Cloudflare Enforcement Strategy (see ezy-shield repo `docs/internal/adr/`)
- [Cloudflare API Docs: Custom IP Lists](https://developers.cloudflare.com/api/operations/lists-list-lists)
- [Cloudflare Dashboard](https://dash.cloudflare.com)
