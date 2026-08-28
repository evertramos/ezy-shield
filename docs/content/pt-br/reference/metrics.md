---
title: Métricas
description: Referência do endpoint de métricas Prometheus
order: 8
---

# Métricas Prometheus

O EzyShield expõe métricas Prometheus em **`GET /metrics` no listener do
dashboard** (`127.0.0.1:9090` por padrão). Nenhum listener de rede novo é
criado — as métricas usam o dashboard loopback-only existente, conforme a
regra do projeto de nenhum listener novo. Os contadores vivem no daemon e
são proxied pelo unix socket de controle, então o processo do dashboard
precisa do daemon rodando para servir um scrape (503 caso contrário).

Zero dependências: o formato de exposição em texto (0.0.4) é feito à mão
— uma client library do Prometheus seria a maior dependência do binário
por uma página de código de escrita.

## Métricas

| Métrica | Tipo | Labels | Significado |
|---|---|---|---|
| `ezyshield_build_info` | gauge | `version` | Sempre 1; carrega a versão do build |
| `ezyshield_collector_lines_total` | counter | `collector` | Linhas brutas recebidas, por tipo de coletor (`filetail`, `journald`, `docker`, …) |
| `ezyshield_parser_events_total` | counter | `parser` | Eventos estruturados produzidos, por parser (`ssh`, `nginx`, …) |
| `ezyshield_actions_total` | counter | `op` | Ações do motor de decisão (`ban`, `dry_ban`, `notify_only`, `record`, …) |
| `ezyshield_strikes_total` | counter | `level` | Strikes registrados, por nível de escalonamento (1–5) |
| `ezyshield_bans_applied_total` | counter | `enforcer` | Bans aplicados com sucesso, por backend de enforcement |
| `ezyshield_ai_requests_total` | counter | `provider` | Chamadas de análise de IA por provedor |
| `ezyshield_ai_tokens_total` | counter | `provider` | Tokens de IA consumidos (input+output) por provedor |
| `ezyshield_active_bans` | gauge | — | Bans ativos no store no momento do scrape (−1 = consulta ao store falhou) |

A cardinalidade de labels é **limitada por construção**: só existem
labels enumeráveis (tipos de coletor/parser, nomes de operação, níveis de
strike, nomes de enforcer e provedor). IPs, usernames e caminhos nunca
viram valores de label — valores hostis ou inesperados caem em
`invalid`, e cada família limita valores distintos, dobrando o excesso em
`other`.

## Autenticação

Por padrão o `/metrics` exige a autenticação de sessão do dashboard, como
toda rota. Como o Prometheus não faz login de sessão, o scrape
normalmente usa:

```yaml
# /etc/ezyshield/config.yaml
dashboard:
  metrics_auth: false
```

Isso permite scrapes sem autenticação e é aceitável **apenas porque o
listener é loopback-only** — qualquer processo local já consegue observar
a maior parte dessas informações. A rota é limitada de qualquer forma
(120 requisições/min).

## Configuração de scrape

```yaml
# prometheus.yml — Prometheus no mesmo host
scrape_configs:
  - job_name: ezyshield
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

Para um Prometheus remoto, não exponha o dashboard — use túnel
(`ssh -L 9090:127.0.0.1:9090 host`) ou um agente local com remote-write.
O dashboard recusa binds fora do loopback por design.
