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
| `data_dir` | string | `/var/lib/ezyshield` | **Obrigatório** (`config validate` rejeita valor vazio). Diretório de estado usado pelo comando **`dashboard`** — seu banco de auth é `<data_dir>/dashboard.db`. **Não** define o caminho do banco SQLite do daemon: isso é a flag `run --db` (default `/var/lib/ezyshield/ezyshield.db`). |
| `socket_path` | string | `/run/ezyshield/ezyshield.sock` | Caminho do socket de controle ao qual o **`dashboard`** se conecta (unix socket — nunca há listener TCP para controle). **Não** define o socket do daemon: o daemon usa a flag `run --socket` (default `/run/ezyshield/ezyshield.sock`), então um valor customizado precisa casar com `run --socket`, ou o dashboard aponta para um socket que o daemon nunca cria. |
| `rules_dir` | string | `/etc/ezyshield/rules.d` | Customizações de regras via drop-in: todo `*.yaml` aqui faz merge sobre as rules embutidas por `name` e sobrevive a updates (veja o [guia de regras](../guides/rules-customization.md)) |
| `rules_path` | string | — | **Deprecated.** Substitui as rules embutidas por inteiro (sem merge; `rules.d` ignorado) — congela a instalação fora do tuning de regras do upstream |
| `log.level` | string | `info` | `debug` \| `info` \| `warn` \| `error` |
| `collectors` | lista | `[]` | Fontes de log a acompanhar (veja abaixo). Uma lista vazia é válida — o `config validate` emite um aviso e o daemon simplesmente não acompanha nada. |
| `enforce` | objeto | — | Backends de enforcement (opcional — sem ele, as decisões ficam só no log) |
| `notify` | objeto | — | Canais de notificação (opcional) |
| `ai` | objeto | — | Provedor de IA para tráfego ambíguo (opcional) |
| `enrich` | objeto | — | Enriquecimento GeoIP/ASN (opcional) |
| `dashboard` | objeto | — | Endereço de bind e banco de auth do dashboard (opcional) |

> **O daemon ignora `data_dir` e `socket_path`; o comando `dashboard` os
> consome** (e `data_dir` é adicionalmente exigido por `config validate`).
> O daemon (`ezyshield run`) obtém o caminho do banco e o socket de controle das
> suas próprias flags `--db` e `--socket` (defaults `/var/lib/ezyshield/ezyshield.db`
> e `/run/ezyshield/ezyshield.sock`) e não lê essas duas chaves. Defini-las no
> `config.yaml` move o banco de auth do dashboard e o alvo de conexão dele, não
> os arquivos do daemon — então mantenha `socket_path` alinhado com `run --socket`.
> Veja a [referência de CLI](cli.md) para as flags de `run` e `dashboard`.

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
| `parser` | não | força um parser: `nginx` \| `ssh` \| `apache` \| `apache-error` \| `traefik` \| `caddy` (padrão: roteado automaticamente a partir da fonte). `apache` lê o log de **acesso** do Apache (formato combined, compartilhado com `nginx`); `apache-error` lê o **error_log** do Apache (`error.log` / `error_log`). **Honrado apenas para coletores `file` e `docker`** — o `journald` o ignora e sempre roteia o parser a partir da unidade. |

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
  nftables: {}                   # enforcement local ligado; os padrões bastam

  cloudflare:
    api_token: env:CLOUDFLARE_API_TOKEN  # segredos são referências env:, nunca inline — este NOME é o que o init escreve
    account_id: "abc123..."      # obrigatório no modo padrão "lists"
    # mode: lists                # "lists" (padrão) ou "rulesets"
    # list_name: ezyshield_blocked
    # zone_ids: [ ... ]          # obrigatório apenas com mode: rulesets
    # action: block              # padrão
```

### nftables

| Campo | Padrão | Descrição |
|-------|--------|-----------|
| `table` | `inet ezyshield` | tabela nftables (todas as regras do EzyShield vivem dentro dela). `<nome>` ou `inet <nome>`; a família `inet` é a única suportada (layout dual-stack v4+v6). Nomes: letras, dígitos, underscore |
| `set` | `blocked` | set que guarda os endereços IPv4 banidos; o gêmeo IPv6 é derivado automaticamente como `<set>6` (padrão `blocked6`). `allowed`/`allowed6` são reservados para os sets de allowlist |
| `socket` | `/run/ezyshield-enforcer/enforcer.sock` | socket do helper privilegiado do enforcer |

Os dois são opcionais e genuinamente respeitados: o daemon os repassa ao
enforcer privilegiado, que os revalida de forma independente antes de
escrever qualquer regra. Duas notas operacionais para nomes customizados:

- O enforcer precisa suportá-los (mesma versão do daemon). Contra um
  `ezyshield-enforcer` mais antigo, o daemon se recusa a aplicar com um erro
  claro em vez de usar os padrões silenciosamente.
- O enforcer aplica um conjunto de nomes por execução. Depois de mudar
  `table`/`set`, reinicie os dois serviços (`sudo systemctl restart
  ezyshield-enforcer ezyshield`); uma tabela antiga deixada por uma renomeação
  pode ser removida com `nft delete table inet <nome-antigo>`.

### cloudflare

| Campo | Obrigatório | Descrição |
|-------|-------------|-----------|
| `api_token` | sim | referência `env:VARNAME` para um API token com escopo restrito |
| `mode` | não | `lists` (padrão — IP List no nível da conta + regras WAF) ou `rulesets` (regras por zona) |
| `account_id` | com `mode: lists` | ID da conta Cloudflare |
| `list_name` | não | nome da IP list (padrão `ezyshield_blocked`) |
| `instance` | não | Identidade deste servidor quando vários servidores compartilham uma conta Cloudflare (o plano free permite uma única lista): cada daemon marca seus itens como `ezyshield:<instance>` e gerencia só os próprios — os bans de todos os servidores se somam em vez de se sobrescreverem. Padrão: hostname; deve casar com `[A-Za-z0-9._-]{1,32}` e permanecer estável entre restarts |
| `adopt_legacy_items` | não | Ative em **exatamente um** servidor da conta para assumir os itens escritos por versões antigas (comentário `ezyshield` sem instância) e voltar a expirá-los. Remova quando esses itens acabarem |
| `zone_ids` | com `mode: rulesets` | zonas às quais anexar as regras |
| `action` | não | `block` (padrão), `challenge` ou `js_challenge` |
| `name` | não | rótulo exibido na saída de status/test |
| `debounce` | não | por quanto tempo mutações rápidas de ban/unban são agrupadas antes de um único push à API (duração Go, padrão `15s`) |
| `expire_flush_interval` | não | cadência das **remoções** de itens em lote no modo `lists` (duração Go, padrão `3m`) — bans expirados e unbans acumulam e saem em uma única chamada de API por intervalo |

Múltiplas contas Cloudflare são suportadas: `cloudflare` também aceita uma **lista** desses objetos. Veja o [guia da Cloudflare](../guides/cloudflare.md).

Ajustar as duas cadências troca velocidade de propagação no edge por menos
chamadas de API. Os padrões mantêm um servidor movimentado confortavelmente
dentro do limite da Lists API da Cloudflare; aumente-os se o `ezyshield
status` ainda reportar throttling (`ratelimited` no detalhe do enforcement) e
diminua o `debounce` se um ban novo precisar chegar ao edge mais rápido. As
remoções são deliberadamente o caminho lento: um IP expirado permanecer
bloqueado no edge por até `expire_flush_interval` é fail-closed e inofensivo,
enquanto um *ban* atrasado é exposição real — por isso bans seguem o
`debounce` e apenas remoções esperam o intervalo de flush. O `ezyshield
unban` manual também propaga ao edge na cadência do flush (o unban local no
nftables é imediato).

## notify

```yaml
notify:
  rate_limit_per_minute: 5       # padrão — teto de notificações por minuto
  dedup_window_sec: 600          # padrão — alertas idênticos são colapsados
  notify_only_window_sec: 3600   # padrão — notify_only repetido por (IP, regra) vira um único resumo

  telegram:
    bot_token: env:TELEGRAM_BOT_TOKEN
    chat_ids: ["123456789"]
    severity: [warn, critical]   # filtro opcional: info | warn | critical

  email:
    host: smtp.example.com
    port: 587
    username: alerts@example.com
    password: env:SMTP_PASSWORD
    tls: starttls                # starttls (padrão) | tls | none
    from: alerts@example.com
    to: [admin@example.com]

  slack:
    webhook_url: env:SLACK_WEBHOOK_URL
    channel: "#security"         # override opcional

  discord:
    webhook_url: env:DISCORD_WEBHOOK_URL

  webhook:
    url: env:WEBHOOK_URL
    headers:
      Authorization: env:WEBHOOK_AUTH_TOKEN   # o valor precisa ser uma referência env: completa
```

Campos compartilhados: `rate_limit_per_minute` (padrão 5) e `dedup_window_sec` (padrão 600) protegem contra tempestades de notificação. `notify_only_window_sec` (padrão 3600) adicionalmente janela os eventos `notify_only` abaixo do limiar por (IP, regra): o primeiro evento notifica na hora e as repetições dentro da janela viram um único resumo — valor negativo desativa. Entradas do audit log nunca são suprimidas. Todo canal aceita uma lista `severity` opcional (`info` \| `warn` \| `critical`).

> Campos do tipo segredo (`bot_token`, `password`, `webhook_url`, o `url` do webhook) só aceitam referências `env:VARNAME` — valores inline são rejeitados no carregamento. Eles também são **obrigatórios** no seu canal: um bloco `telegram` sem `bot_token`, um `email` sem `password`, ou um `slack`/`discord`/`webhook` sem sua URL falha na validação (o daemon os resolve na inicialização). Os **valores** dos headers do webhook são enviados literalmente, a menos que o valor inteiro seja uma referência `env:`, que é resolvida.

> O `tls: starttls` do email **falha fechado**: se o servidor SMTP não anunciar STARTTLS (ou um proxy que remove capacidades o esconder), o envio dá erro em vez de silenciosamente cair para texto puro. Defina `tls: none` explicitamente se realmente pretende enviar sem criptografia.

## ai

Opcional — sem o bloco `ai`, o rule engine determinístico cuida de tudo.

```yaml
# Provedor único
ai:
  provider: anthropic            # anthropic | openai | ollama
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 69]       # scores nesta faixa consultam a IA (mantenha high < ban_threshold)
  token_budget_daily: 50000      # teto diário rígido; além dele o rule engine assume
  cache_ttl: 15m                 # cache de vereditos idênticos (padrão 15m)
```

```yaml
# Ou failover multi-provedor
ai:
  providers:
    - name: anthropic
      priority: 1
      model: claude-haiku-4-5-20251001
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
| `endpoint` | URL base apenas para o provedor **`ollama`** (padrão `http://localhost:11434`). Os provedores `anthropic` e `openai` a ignoram e sempre chamam suas APIs oficiais (`https://api.anthropic.com`, `https://api.openai.com`) — não há override de endpoint compatível com OpenAI. Mesmo comportamento nas formas de provedor único e de failover `providers`. |
| `ambiguous_band` | `[low, high]` — apenas scores dentro da faixa consultam a IA. Omitida (ou `[0, 0]`) assume `[30, ban_threshold − 1]`, seguindo o ban_threshold CONFIGURADO na policy.yaml (`[30, 69]` com o limiar padrão de 70) — então elevar o limiar alarga automaticamente a faixa omitida em vez de deixar silenciosamente uma lacuna sem consulta; qualquer outra faixa com `low >= high` ou valores fora de 0–100 é rejeitada no carregamento. Mantenha `high` **abaixo** do `ban_threshold` da policy: um score no limiar ou acima já decidiu o ban só com as regras, então o daemon nunca consulta a IA para ele — uma faixa que invade o limiar apenas dispara um aviso no start e no `validate` |
| `token_budget_daily` | teto diário de tokens; quando esgotado, as decisões voltam para as rules |
| `cache_ttl` | duração do cache de vereditos; omitido ou `0` significa o padrão de **15m** (o cache não pode ser desativado — é o segundo freio contra consultas repetidas para o mesmo comportamento). As entradas são indexadas pela assinatura de comportamento (contagem de kinds + janela), não pelo IP — padrões de ataque idênticos de IPs diferentes reutilizam um veredito; num hit o veredito em cache é redirecionado para o IP em avaliação. Vereditos clampados por allowlist nunca são cacheados |
| `providers` | lista de failover multi-provedor (`name`, `priority`, `model`, `api_key`, `endpoint`, `token_budget_daily`); tem precedência sobre os campos de provedor único |

O veredito da IA é sempre consultivo: validado por schema, limitado pela policy e nunca capaz de banir um IP da allowlist.

Cada chamada de IA é registrada na tabela `ai_usage` com o IP analisado, então a atribuição de custo vira uma única consulta — os maiores gastadores (um IP drenando o orçamento é, por si só, sintoma de vazamento):

```bash
sudo sqlite3 /var/lib/ezyshield/ezyshield.db \
  "SELECT ip, COUNT(*) calls, ROUND(SUM(cost_usd), 4) usd
   FROM ai_usage WHERE ip IS NOT NULL
   GROUP BY ip ORDER BY usd DESC LIMIT 10;"
```

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

## webshell_watch

Tripwire de webshell (opt-in): varre web roots por arquivos web executáveis novos ou modificados. Puramente observacional — audit + notificação, nunca ban. Veja o [guia Tripwire de Webshell](../guides/webshell-tripwire.md).

| Campo | Padrão | Descrição |
|-------|--------|-----------|
| `enabled` | `false` | Chave de opt-in |
| `roots` | — | Diretórios web-root absolutos a varrer (**obrigatório** quando habilitado) |
| `extensions` | `.php, .phtml, .php5, .php7, .phar` | Extensões vigiadas (com ponto inicial) |
| `ignore` | `[]` | Padrões de caminho a ignorar — globs `path.Match`, ou substring quando o padrão não tem metacaracteres de glob |
| `interval_sec` | `10` | Cadência da varredura em segundos (mínimo 5) |

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
