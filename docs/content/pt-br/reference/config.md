---
title: Referência de Config
description: Referência completa de config.yaml
order: 2
---

# Referência de Config

Referência completa de `/etc/ezyshield/config.yaml` — fontes de log, backends de enforcement, notificações, IA, enriquecimento e o dashboard. O arquivo é validado de forma estrita: chaves desconhecidas são rejeitadas com o número exato da linha.

> `ezyshield init` e os wizards `ezyshield config <componente>` escrevem em `/etc/ezyshield` e precisam de `sudo` — falham imediatamente com a dica antes de qualquer pergunta. Valide qualquer edição manual com `ezyshield config validate`.

## Nível superior

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `data_dir` | string | `/var/lib/ezyshield` | Diretório de estado; o banco SQLite fica em `<data_dir>/ezyshield.db` |
| `socket_path` | string | `/run/ezyshield/ezyshield.sock` | Socket de controle do daemon (unix socket — nunca há listener TCP para controle) |
| `rules_dir` | string | `/etc/ezyshield/rules.d` | Customizações de regras via drop-in: todo `*.yaml` aqui faz merge sobre as rules embutidas por `name` e sobrevive a updates (veja o [guia de regras](../guides/rules-customization.md)) |
| `rules_path` | string | — | **Deprecated.** Substitui as rules embutidas por inteiro (sem merge; `rules.d` ignorado) — congela a instalação fora do tuning de regras do upstream |
| `log.level` | string | `info` | `debug` \| `info` \| `warn` \| `error` |
| `collectors` | lista | `[]` | Fontes de log a acompanhar (veja abaixo) |
| `enforce` | objeto | — | Backends de enforcement (opcional — sem ele, as decisões ficam só no log) |
| `notify` | objeto | — | Canais de notificação (opcional) |
| `ai` | objeto | — | Provedor de IA para tráfego ambíguo (opcional) |
| `enrich` | objeto | — | Enriquecimento GeoIP/ASN (opcional) |
| `dashboard` | objeto | — | Endereço de bind e banco de auth do dashboard (opcional) |

## collectors

Cada entrada acompanha uma fonte de log. `kind` seleciona a fonte; cada kind exige um campo extra.

```yaml
collectors:
  - kind: journald
    unit: ssh                    # unit systemd a acompanhar

  - kind: file
    path: /var/log/nginx/access.log

  - kind: docker
    container: wordpress-nginx   # nome, ID curto ou ID completo
    parser: nginx                # override opcional de parser
```

| Campo | Obrigatório | Descrição |
|-------|-------------|-----------|
| `kind` | sim | `file` \| `journald` \| `docker` |
| `path` | para `file` | arquivo a acompanhar |
| `unit` | para `journald` | unit systemd a acompanhar |
| `container` | para `docker` | nome do container, ID curto ou ID completo |
| `parser` | não | força um parser: `nginx` \| `ssh` \| `apache` \| `apache-error` \| `traefik` \| `caddy` (padrão: roteado automaticamente a partir da fonte) |

### Coletor SSH (nome do unit varia por distro)

O nome do unit systemd do SSH **depende da distro**: é `ssh` no Debian/Ubuntu e
`sshd` no RHEL/CentOS/Fedora/Rocky/Alma, Arch e SUSE. Use o nome que
`systemctl status <unit>` resolve no seu host — um alias que o `journalctl -u`
não reconhece coleta zero eventos.

```yaml
collectors:
  - kind: journald
    unit: ssh    # Debian/Ubuntu; use "sshd" no RHEL/CentOS/Arch/SUSE
```

Para ler o SSH de um arquivo em vez do journald, aponte para o log de auth da
sua distro — `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (família
RHEL). Os dois formatos de timestamp são aceitos: o legado (`Jan  1 12:00:00`) e
o ISO-8601 moderno (`2026-07-13T22:57:35+00:00`).

> **Configure apenas um coletor de SSH por host** — journald **ou** o arquivo que
> ele alimenta, nunca os dois. Ler ambos ingere cada evento duas vezes, o que
> conta em dobro para os limiares de detecção. (Um IP já banido nunca é banido de
> novo, então isso nunca gera bans duplicados, apenas detecção mais cedo.)

## enforce

```yaml
enforce:
  nftables:
    table: ezyshield             # padrão
    set: banned                  # padrão

  cloudflare:
    api_token: env:CF_API_TOKEN  # segredos são referências env:, nunca inline
    account_id: "abc123..."      # obrigatório no modo padrão "lists"
    # mode: lists                # "lists" (padrão) ou "rulesets"
    # list_name: ezyshield_blocked
    # zone_ids: [ ... ]          # obrigatório apenas com mode: rulesets
    # action: block              # padrão
```

### nftables

| Campo | Padrão | Descrição |
|-------|--------|-----------|
| `table` | `ezyshield` | tabela nftables (todas as regras do EzyShield vivem dentro dela) |
| `set` | `banned` | set que guarda os endereços banidos |
| `socket` | `/run/ezyshield-enforcer/enforcer.sock` | socket do helper privilegiado do enforcer |

### cloudflare

| Campo | Obrigatório | Descrição |
|-------|-------------|-----------|
| `api_token` | sim | referência `env:VARNAME` para um API token com escopo restrito |
| `mode` | não | `lists` (padrão — IP List no nível da conta + regras WAF) ou `rulesets` (regras por zona) |
| `account_id` | com `mode: lists` | ID da conta Cloudflare |
| `list_name` | não | nome da IP list (padrão `ezyshield_blocked`) |
| `zone_ids` | com `mode: rulesets` | zonas às quais anexar as regras |
| `action` | não | `block` (padrão), `challenge` ou `js_challenge` |
| `name` | não | rótulo exibido na saída de status/test |

Múltiplas contas Cloudflare são suportadas: `cloudflare` também aceita uma **lista** desses objetos. Veja o [guia da Cloudflare](../guides/cloudflare.md).

## notify

```yaml
notify:
  rate_limit_per_minute: 5       # padrão — teto de notificações por minuto
  dedup_window_sec: 600          # padrão — alertas idênticos são colapsados

  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_TOKEN
    chat_ids: ["123456789"]
    severity: [warn, critical]   # filtro opcional: info | warn | critical

  email:
    host: smtp.example.com
    port: 587
    username: alerts@example.com
    password: env:EZYSHIELD_SMTP_PASSWORD
    tls: starttls                # starttls (padrão) | tls | none
    from: alerts@example.com
    to: [admin@example.com]

  slack:
    webhook_url: env:EZYSHIELD_SLACK_WEBHOOK
    channel: "#security"         # override opcional

  discord:
    webhook_url: env:EZYSHIELD_DISCORD_WEBHOOK

  webhook:
    url: env:EZYSHIELD_WEBHOOK_URL
    headers:
      Authorization: env:EZYSHIELD_WEBHOOK_TOKEN   # o valor precisa ser uma referência env: completa
```

Campos compartilhados: `rate_limit_per_minute` (padrão 5) e `dedup_window_sec` (padrão 600) protegem contra tempestades de notificação. Todo canal aceita uma lista `severity` opcional (`info` \| `warn` \| `critical`).

> Campos do tipo segredo (`bot_token`, `password`, `webhook_url`, o `url` do webhook) só aceitam referências `env:VARNAME` — valores inline são rejeitados no carregamento. Os **valores** dos headers do webhook são enviados literalmente, a menos que o valor inteiro seja uma referência `env:`, que é resolvida.

## ai

Opcional — sem o bloco `ai`, o rule engine determinístico cuida de tudo.

```yaml
# Provedor único
ai:
  provider: anthropic            # anthropic | openai | ollama
  model: claude-3-5-haiku-latest
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 75]       # scores nesta faixa consultam a IA
  token_budget_daily: 50000      # teto diário rígido; além dele o rule engine assume
  cache_ttl: 1h                  # cache de vereditos idênticos
```

```yaml
# Ou failover multi-provedor
ai:
  providers:
    - name: anthropic
      priority: 1
      model: claude-3-5-haiku-latest
      api_key: env:ANTHROPIC_API_KEY
    - name: ollama
      priority: 2
      model: llama3
      endpoint: http://localhost:11434
```

| Campo | Descrição |
|-------|-----------|
| `provider` | `anthropic` \| `openai` \| `ollama` (forma de provedor único) |
| `model` | nome do modelo |
| `api_key` | referência `env:VARNAME` (nunca inline) |
| `endpoint` | URL base — usada pelo ollama (padrão `http://localhost:11434`) e por endpoints compatíveis com OpenAI |
| `ambiguous_band` | `[low, high]` — apenas scores dentro da faixa consultam a IA |
| `token_budget_daily` | teto diário de tokens; quando esgotado, as decisões voltam para as rules |
| `cache_ttl` | duração do cache de vereditos |
| `providers` | lista de failover multi-provedor (`name`, `priority`, `model`, `api_key`, `endpoint`, `token_budget_daily`); tem precedência sobre os campos de provedor único |

O veredito da IA é sempre consultivo: validado por schema, limitado pela policy e nunca capaz de banir um IP da allowlist.

## enrich (GeoIP/ASN)

Enriquecimento GeoIP/ASN — habilita `block_countries` / `block_asns` no policy e as colunas de país/ASN em `list` e `report`. Opcional: sem a seção `enrich:` o daemon roda normalmente com enriquecimento vazio (sem país/ASN em lugar nenhum, e essas chaves de policy nunca casam).

| Campo | Descrição |
|-------|-----------|
| `db_path` | caminho do `GeoLite2-Country.mmdb` |
| `asn_path` | caminho do `GeoLite2-ASN.mmdb` |
| `auto_update` | o daemon baixa e atualiza os bancos sozinho (semanalmente) |
| `license_key` | referência `env:VARNAME` para uma license key da MaxMind — obrigatória com `auto_update: true`; valores inline são rejeitados |

O caminho mais fácil é o wizard, que conduz por tudo isso:

```bash
sudo ezyshield config enrich maxmind
sudo systemctl restart ezyshield
```

**De onde vêm os bancos.** O EzyShield usa os bancos gratuitos GeoLite2 da MaxMind, que exigem uma conta (gratuita): [cadastre-se](https://www.maxmind.com/en/geolite2/signup) e gere uma license key em *Manage License Keys*. Com `auto_update: true` o daemon baixa os dois bancos sozinho no startup quando os arquivos estão ausentes e os atualiza semanalmente — você nunca manuseia os arquivos:

```yaml
enrich:
  db_path: /var/lib/ezyshield/GeoLite2-Country.mmdb
  asn_path: /var/lib/ezyshield/GeoLite2-ASN.mmdb
  auto_update: true
  license_key: env:MAXMIND_LICENSE_KEY
```

A chave é um segredo como qualquer outro: coloque `MAXMIND_LICENSE_KEY=...` em `/etc/ezyshield/.env` (modo 0600 — o wizard faz isso por você) e referencie como `env:MAXMIND_LICENSE_KEY`. Ela só é usada na URL de download e nunca é logada.

**Alternativa manual.** Com `auto_update: false` nenhuma chave é necessária em runtime: baixe `GeoLite2-Country.mmdb` e `GeoLite2-ASN.mmdb` da sua conta MaxMind (ou espelhe de um host que já os tenha) e coloque nos caminhos configurados. Arquivos ausentes ou ilegíveis não são erro — o daemon loga um aviso e roda com enriquecimento vazio até eles aparecerem.

## dashboard

| Campo | Padrão | Descrição |
|-------|--------|-----------|
| `addr` | `127.0.0.1:9090` | Endereço de bind — **somente loopback**; binds fora do loopback são recusados no startup |
| `auth_db_path` | `<data_dir>/dashboard.db` | Banco de autenticação do dashboard |

## Exemplo mínimo

```yaml
data_dir: /var/lib/ezyshield

collectors:
  - kind: journald
    unit: ssh

enforce:
  nftables: {}
```

## Segredos

Todo campo de segredo recebe uma referência `env:VARNAME`, resolvida pelo daemon (`ezyshield run`) a partir do ambiente dele. Os wizards gravam os valores em `/etc/ezyshield/.env` (modo 0600), que a unit do systemd carrega via `EnvironmentFile=`. Segredos nunca aparecem no config.yaml, em logs ou em mensagens de erro.

Isso também vale na direção inversa: se um valor colado em um campo *não-secreto* (provider, model, endpoint, ...) parecer uma credencial — um prefixo de chave conhecido como `sk-`, ou um token longo de alta entropia — o config é rejeitado no carregamento com um erro que nomeia o campo mas nunca imprime o valor. Os headers de webhook são a única exceção (valores crus são legais ali e são redigidos no `config show`).

## Validação

```bash
sudo ezyshield config validate   # schema estrito + constraints, número exato da linha nos erros
sudo ezyshield doctor            # checagem do ambiente (arquivos, permissões, sockets)
sudo ezyshield test enforcer all # exercita os backends de enforcement de verdade
sudo ezyshield test notifier all # envia uma notificação de teste para cada canal
```
