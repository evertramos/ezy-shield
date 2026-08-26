---
title: Detecção Low-and-Slow
description: Pegando atacantes SSH que se cadenciam abaixo dos thresholds horários
order: 10
---

# Detecção Low-and-Slow de SSH

Brute force em rajada é fácil: muitas falhas de um IP em segundos. O oponente mais difícil se cadencia — uma tentativa a cada 10 minutos, a cada hora, ou uma por dia — ficando abaixo de todo threshold de janela curta para sempre. O EzyShield fecha esse ponto cego com **contadores persistentes por IP por hora** e duas regras de janela longa.

## Os níveis de detecção

| Nível | Regra | Janela | Threshold | Pega |
|---|---|---|---|---|
| Rajada | `ssh_bruteforce` | 60s | 5 | brute force clássico, na hora |
| Sustentado | `ssh_bruteforce_sustained` | 1h | 10 | ~1 tentativa a cada 6 min |
| Diário | `ssh_bruteforce_daily` | 24h | 5 | cadência de 10 min / horária |
| Semanal | `ssh_bruteforce_weekly` | 7d | 5 | o retentador de ~1 vez por dia |

Os quatro alimentam o mesmo pipeline de decisão: supremacia da allowlist, anti-lockout, dry-run por padrão e a escada de strikes (primeiro strike = ban recuperável de 5 minutos) valem sem mudança.

## Como funciona

Janelas de até 1 hora continuam no agregador de janela deslizante em memória. Janelas **acima** de 1 hora são servidas por contadores agregados em disco: uma linha SQLite por `(ip, kind, hora)`, incrementada no lugar. Esse desenho importa por três motivos:

- **RAM quase zero.** Um IP falhando 100× numa hora é uma linha incrementada 100 vezes — nenhum horizonte de 24h de eventos fica em memória.
- **Sobrevive a eviction e restarts.** O cap LRU do agregador em memória e restarts do daemon são exatamente o que um atacante lento supera esperando; contadores em disco não esquecem.
- **Só contagens.** A tabela guarda `ip + kind + hora + count` — nunca usernames, paths ou linhas de log cruas. Apenas kinds SSH referenciados por regras de janela longa são gravados; tráfego HTTP nunca toca nela. Buckets mais antigos que a maior janela longa são podados automaticamente.

Como os contadores não guardam valores de campo, regras com `window` acima de 1h precisam ser por kind — matchers `field`/`value`/`contains` são rejeitados no carregamento com erro claro.

## O trade-off de falso positivo

Um humano que erra a senha falha uma ou duas vezes e então corrige ou desiste. Automação moendo uma credencial morta tenta para sempre. Os thresholds codificam essa diferença:

- 1–2 falhas, qualquer cadência: nunca acionado.
- 3–4 falhas espalhadas por dias: ainda abaixo de todo threshold.
- 5 falhas acumuladas num dia (ou ao longo de 5 dias no nível semanal): acionado — e o primeiro strike é um ban de 5 minutos, então até um falso positivo é recuperável e se resolve sozinho.

**A latência de detecção é inerente**: um atacante de 1 tentativa/hora é pego na 5ª tentativa (~5 horas); um retentador de 1/dia, no 5º dia. Uma vez na escada de strikes, reincidências escalam pelos TTLs normais (5m → 1h → 24h → 7d → permanente).

## Ajuste

Sobrescreva thresholds com um drop-in em `rules.d` (mesclado por nome de regra):

```yaml
# /etc/ezyshield/rules.d/60-local-tuning.yaml
rules:
  - name: ssh_bruteforce_daily
    description: "Low-and-slow SSH brute force (daily accumulation)"
    kinds: [ssh_fail, ssh_invalid_user]
    window: 86400s
    threshold: 8        # host mais tolerante (NAT de escritório compartilhado)
    score: 75
    category: bruteforce
```

Abaixar thresholds para menos de 5 aumenta a exposição a falso positivo em IPs compartilhados (NAT de escritório, CGNAT); aumentar as janelas estende por quanto tempo os buckets de contadores ficam retidos em disco.
