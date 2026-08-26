---
title: Migrando do fail2ban
description: Leia seus jails do fail2ban e gere um setup EzyShield equivalente
order: 10
---

# Migrando do fail2ban

`ezyshield migrate fail2ban` lê sua instalação do fail2ban — `jail.conf`, `jail.local` e `jail.d/` com a precedência do próprio fail2ban — e gera uma **proposta**: um `config.yaml`, um `policy.yaml` e um `REPORT.md` explicando cada decisão. Nunca toca `/etc` sem você pedir explicitamente.

```console
$ sudo ezyshield migrate fail2ban
wrote ezyshield-migration (config.yaml, policy.yaml, REPORT.md)
mapped 3 jail(s), 1 unmapped, 4 disabled/skipped — details in REPORT.md
the generated policy is armed: false (dry-run) — review, run 'ezyshield doctor', watch a
week of dry-run output, then arm with 'ezyshield arm'
```

Flags:

- `--from DIR` — diretório de config do fail2ban (padrão `/etc/fail2ban`)
- `--out DIR` — onde escrever a proposta (padrão `./ezyshield-migration`)
- `--write` — escreve direto em `/etc/ezyshield`; recusa sobrescrever arquivos existentes sem `--force`. Sempre `armed: false`.
- `--json` — resumo legível por máquina (`mapped`, `unmapped`, `skipped`, `allowlist`, `warnings`)

## O que mapeia para quê (v1)

| fail2ban | EzyShield |
|---|---|
| jail `sshd` | collector journald de SSH + família de regras `ssh_bruteforce` embutida |
| jails `nginx-*` | collectors de arquivo com parser nginx + regras HTTP embutidas |
| jails `apache-*` | collectors com parser apache |
| `recidive` | coberto nativamente — a escada de strikes escala reincidentes |
| `ignoreip` | entradas de `allowlist:` no policy.yaml (só IPs/CIDRs validados; hostnames nunca são resolvidos, são reportados) |
| `maxretry` / `findtime` | sem equivalente 1:1 — as regras embutidas têm thresholds ajustáveis via drop-ins em `rules.d` (anotado no report) |
| `bantime` | **sugestão** de TTL do strike 1 no report apenas — o EzyShield escala, o fail2ban bane por tempo fixo |
| jails `postfix*` / `dovecot` | reportados como *parser planejado* — mantenha esses jails no fail2ban até os parsers saírem |
| jails/filtros customizados | listados no report com o nome do filtro; filtros regex nunca são traduzidos |

Jails desabilitados são pulados (e listados). O leitor é defensivo: arquivos ilegíveis ou malformados, entradas gigantes e valores com `%(...)s` são reportados na seção *Reader warnings* — um arquivo quebrado nunca aborta a execução.

## Sequência recomendada

1. Rode a migração e **leia o REPORT.md** — ele explica o que mapeou, o que não, e por quê.
2. Instale a proposta (copie os arquivos, ou re-rode com `--write`).
3. `ezyshield doctor`, depois rode **uma semana em dry-run** — as duas ferramentas podem rodar lado a lado com segurança (redundante, não danoso).
4. `ezyshield arm` quando a saída do dry-run estiver certa.
5. Só então desabilite o fail2ban.
