# Cloudflare Edge Enforcement

This guide walks you through setting up EzyShield to block malicious IPs at the Cloudflare edge using the **Lists mode** (recommended for most deployments).

## Modes Overview

EzyShield supports two Cloudflare enforcement modes:

| Feature | Lists (Recommended) | Rulesets (Legacy) |
|---------|------------------|-------------------|
| **API calls per ban** | 1 (account-level) | 1 per zone |
| **IP capacity** | 10,000 | ~200 per rule |
| **Multi-zone support** | Automatic | Per-zone rules |
| **WAF rule setup** | Auto-managed | Manual per zone |
| **Free plan** | ✅ (1 list, 10k items) | ✅ |
| **Least privilege** | ❌ (needs account-level token) | ✅ (zone-level token) |

**Lists mode** is recommended unless you need per-zone control or cannot use account-level tokens.

## Lists Mode Setup

### Step 1: Create Cloudflare API Token

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Go to **Account → API Tokens** (bottom left sidebar)
3. Click **Create Token** and select **Custom token**
4. Configure the token with these permissions:
   - **Account → Account Filter Lists → Edit** (required for managing the IP list)
   - For each zone you want to auto-manage WAF rules:
     - **Zone → Firewall Services → Edit** (optional; required if using `zone_ids`)
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
ezyshield doctor cloudflare
```

This command will:
- Verify the API token has correct permissions
- Test connectivity to Cloudflare
- List accessible zones
- Show the list status (created, item count, etc.)

### Step 5: (Optional) Manual WAF Rule Setup

**If you did NOT configure `zone_ids`** in step 3, you must create the WAF Custom Rule manually for each zone:

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

## Rulesets Mode Setup (Legacy)

For deployments that need per-zone control or cannot use account-level tokens:

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
3. Run `ezyshield doctor cloudflare` to check permission errors
4. Check logs: `ezyshield status` → look for Cloudflare entries

### "List at capacity" (10k items)

If you hit the 10k-item free-plan limit, you have two options:
1. Use **Rulesets mode** (no limit per rule, but ~200 per rule)
2. Upgrade to Cloudflare's paid plan for higher limits

## Multi-Account Setup

To manage multiple Cloudflare accounts from a single EzyShield daemon:

```yaml
enforce:
  cloudflare:
    # Account 1
    - name: client_a
      api_token: env:EZYSHIELD_CF_TOKEN_A
      mode: lists
      account_id: account_a_id
      zone_ids: [zone_a1, zone_a2]
    # Account 2
    - name: client_b
      api_token: env:EZYSHIELD_CF_TOKEN_B
      mode: lists
      account_id: account_b_id
```

Each account gets independent list management. Logs will show `enforce/cloudflare[client_a]` and `enforce/cloudflare[client_b]` for clarity.

## Rate Limiting

EzyShield enforces a 4 requests/second rate limit on Cloudflare API calls to stay well below the public API limits. This is automatically managed and requires no configuration.

## Security Considerations

- API tokens are resolved at daemon startup and never logged
- Tokens are not included in error messages or logs
- Always use `env:VARNAME` references; inline tokens in config are rejected at load time
- Restrict token permissions and IP addresses in Cloudflare settings when possible
- The account-level token can modify your Custom IP Lists — restrict access accordingly

## Validating Your Configuration

### Using `test-enforce cloudflare`

After configuration, validate your setup with:

```bash
ezyshield test-enforce cloudflare --config-dir /etc/ezyshield/
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
✓ Zone WAF access: Zone unaids.org.br (zone_id: aaa111) — WAF rule access OK
✗ Zone WAF access: Zone deupositivo.org (zone_id: ccc333) — 403 Forbidden
  └─ Ensure token has Zone:Firewall Services:Edit on this zone

Result: 4/5 checks passed, 1 failed
```

**Exit code**: 0 if all checks pass, 1 if any check fails

**JSON output**: Use `--json` flag for structured output suitable for automation

## See Also

- [ADR-0002: Cloudflare Enforcement Strategy](../../docs/adr/0002-cloudflare-rulesets-api-over-ip-access-rules.md)
- [Cloudflare API Docs: Custom IP Lists](https://developers.cloudflare.com/api/operations/lists-list-lists)
- [Cloudflare Dashboard](https://dash.cloudflare.com)
