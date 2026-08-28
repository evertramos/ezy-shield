---
title: Deploying to AWS WAF
description: Block IPs at the AWS edge with WAFv2 IPSets (CloudFront/ALB)
order: 3
---

# AWS WAF Edge Enforcement

Block malicious IPs at the AWS edge. When your traffic enters through
CloudFront or an Application Load Balancer, your origin firewall only ever
sees AWS's addresses at the TCP layer — a local nftables ban does not stop
the attacker at the door. The AWS WAF enforcer maintains dedicated WAFv2
**IPSets** (one IPv4, one IPv6) that your WebACL rules reference, so bans
take effect at the edge.

**Ownership boundary**: EzyShield only ever updates the *member addresses*
of the IPSets you designate in config. It never creates, deletes, or
modifies WebACLs, rules, or any other WAF resource — you stay in control
of how (block, count, CAPTCHA) and where the sets are enforced.

## 1. Create the IPSets and WebACL rule

In the AWS console (WAF & Shield → IP sets), create two empty IP sets:

- `ezyshield-v4` — IP version: IPv4
- `ezyshield-v6` — IP version: IPv6
- Scope: **Regional** (for ALB/API Gateway; pick your region) or
  **CloudFront** (global — created in us-east-1)

Then add a rule to your WebACL: *"If request IP originates from IP set
`ezyshield-v4` (or `ezyshield-v6`) → Block"*. Note each set's **Name** and
**Id** (both shown in the console; the Id is the UUID in the set's ARN).

## 2. IAM policy (minimal, from ADR-0012)

The credentials EzyShield uses need exactly this — scoped to the two
IPSets, nothing else (replace REGION/ACCOUNT/ID4/ID6; for CloudFront scope
the ARN segment is `global/ipset/...` and the region in the ARN is
us-east-1):

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

Never grant the enforcer `CreateIPSet`, any WebACL permission, or a
wildcard resource.

## 3. Credentials — never in EzyShield config

Credentials come from the **standard AWS chain**, in this order:

1. Env vars: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
   (+ `AWS_SESSION_TOKEN`) — for systemd, put them in
   `/etc/ezyshield/ezyshield.env` (mode 0600)
2. Shared file: `~/.aws/credentials` (honors `AWS_PROFILE` and
   `AWS_SHARED_CREDENTIALS_FILE`)
3. EC2 instance role via IMDSv2

They are **never** written to `config.yaml` — validation rejects anything
that looks like pasted key material, and the config section has no
credential fields at all. SSO login flows and client-side AssumeRole are
not supported (ADR-0012): mint session credentials externally and provide
them via env vars or the shared file.

## 4. Configure EzyShield

`ezyshield init` offers AWS WAF in the CDN/edge step (it validates
credentials and `GetIPSet` on each set before writing anything), or add
the section by hand:

```yaml
enforce:
  aws_waf:
    scope: regional          # or: cloudfront (global; region is pinned to us-east-1)
    region: eu-west-1        # required for scope: regional
    ipset_v4:
      name: ezyshield-v4
      id: aaaabbbb-cccc-dddd-eeee-ffff00001111
    ipset_v6:
      name: ezyshield-v6
      id: aaaabbbb-cccc-dddd-eeee-ffff00002222
```

Then verify and (initially) stay in dry-run:

```bash
ezyshield doctor        # checks credentials + GetIPSet on each designated set
ezyshield status        # confirm the daemon runs with the enforcer attached
```

**Dry-run first**: with `armed: false` (the default) bans are simulated
and logged, and nothing is pushed to AWS. Watch `ezyshield watch` for a
day, then `ezyshield arm`.

## Capacity and behavior notes

- **10,000 addresses per IPSet** (AWS limit). Beyond it, EzyShield keeps
  the most recent bans and logs a loud warning about what was dropped.
- Every mutation is read-modify-write with WAFv2's optimistic lock
  (`LockToken`); concurrent editors are retried against a fresh read.
  Avoid pointing two EzyShield instances at the same IPSets.
- Addresses are always CIDR-normalized (`/32`, `/128`); IPv6-mapped IPv4
  addresses land in the v4 set.
- A family with no designated IPSet is skipped with a warning — local
  nftables still covers it at the origin.
- The allowlist is checked before any API call, and the daemon's central
  allowlist/anti-lockout gate runs ahead of this enforcer like every
  other backend — a protected address can never reach AWS.
- WAF rule evaluation at the edge means the origin still receives traffic
  that AWS lets through; keep local enforcement enabled as the second
  layer.
