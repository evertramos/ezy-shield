---
title: Feeds de Reputação
description: Use blocklists públicas de IP como sinal extra ou fonte de bloqueio
order: 16
---

# Feeds de Reputação

## O que são

Feeds públicos de reputação de IP (Spamhaus DROP, FireHOL, exports do
AbuseIPDB) listam endereços vistos atacando os servidores *dos outros*. O
EzyShield pode importá-los como sinal extra — ou bloqueá-los direto no
firewall — mantendo-os estritamente separados de tudo que o seu próprio
servidor observou.

```yaml
# /etc/ezyshield/config.yaml
feeds:
  - name: spamhaus-drop
    url: https://www.spamhaus.org/drop/drop.txt
    format: cidr
    refresh_interval: 12h
    action: observe            # ou: block
```

Formatos: `plain` (um IP por linha), `cidr` (IP ou prefixo por linha,
comentários `;`/`#` — Spamhaus DROP e FireHOL), `abuseipdb` (export de
lista plain). Respeite a política de uso de cada feed — o exemplo anotado
em `configs/config.yaml` traz notas por feed (o Spamhaus pede no máximo
dois fetches por dia; exports do AbuseIPDB exigem conta).

## observe vs block

- **`action: observe`** (padrão): as entradas vivem só na memória do
  daemon como *flag de reputação*. Quando um IP de feed **também** dispara
  as suas regras locais, o score ganha +15 e o motivo do verdict carrega
  `[reputation:<feed>]`. Feed sozinho nunca cria verdict, strike ou ban —
  o relato de terceiros é corroboração, não prova.
- **`action: block`**: as entradas são adicionalmente dropadas na borda da
  tabela nftables do ezyshield, em um **set dedicado**.

## Separação de sets — feed não é ban

Entradas de feed nunca tocam a escada de strikes, nunca aparecem no
`ezyshield list` e nunca escrevem no store de bans. Elas vivem em sets
nftables próprios (`blocked_feeds` / `blocked_feeds6`), reconciliados por
inteiro a cada refresh com timeout por elemento (padrão 2× o intervalo de
refresh — um feed morto drena sozinho em vez de bloquear para sempre). Seu
histórico de strikes permanece puramente comportamental: o que o *seu*
servidor observou, com evidência.

Cada refresh escreve uma única linha-resumo no audit log (`feed_refresh`:
entradas, descartadas pelos guardrails, removidas) — nunca uma linha por IP.

## Por que feeds nunca passam por cima da allowlist

Um feed é dado remoto controlado por outra pessoa — trate como
potencialmente envenenado. O EzyShield defende em camadas:

1. **No parsing** (a cada fetch): só parsing estrito de IP/CIDR; faixas
   privadas, loopback, link-local e reservadas sempre descartadas; caps de
   10MiB / 4KiB / contagem de entradas; https obrigatório inclusive em
   redirects; refresh com falha ou lixo mantém o último conjunto bom.
2. **Antes de qualquer apply**: cada entrada é filtrada contra sua
   allowlist e admin CIDRs, seus peers SSH ativos e faixas de CDN
   compartilhadas — overlap nas duas direções: um prefixo largo cobrindo
   seu host admin cai igual ao host em si.
3. **No firewall**: as regras de accept da allowlist ficam *antes* das
   regras de drop dos feeds em todas as chains.
4. `armed: false` (dry-run) não escreve nada no firewall.

## Operando

```bash
ezyshield feeds status        # por feed: último/próximo refresh, entradas, descartadas
ezyshield feeds refresh       # re-baixa todos os feeds agora
ezyshield feeds refresh spamhaus-drop
```

Um "skipped" diferente de zero significa que os guardrails filtraram
entradas — num feed respeitável isso é incomum e merece uma olhada (também
é logado como aviso de possível envenenamento).
