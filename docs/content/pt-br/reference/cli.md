---
title: Referência de CLI
description: Todos os comandos e flags
order: 4
---

# Referência de CLI

Referência completa para a CLI do `ezyshield`.

## Convenções globais

### Códigos de saída

Todos os comandos seguem o mesmo contrato de códigos de saída:

| Código | Significado |
|--------|-------------|
| `0` | Sucesso |
| `1` | Erro de execução — o comando iniciou mas falhou (config inválida, erro de API, falha de escrita) |
| `2` | Erro de uso — comando/flag desconhecido, argumento inválido, ou arquivo de entrada que não existe / não pode ser lido |
| `3` | Daemon inacessível — o socket de controle recusou a conexão (o daemon está em execução?) |

Duas exceções deliberadas: `status` sai com `0` mesmo quando o daemon está
parado (ele reporta o estado com sucesso), e `doctor` sai com `0` mesmo quando
verificações individuais falham (a saída dele é o relatório).

### Saída JSON (`--json`)

Todos os comandos de leitura suportam `--json` com nomes de campos estáveis,
seguros para scripts:

| Comando | Formato |
|---------|---------|
| `status` | Objeto: `daemon`, `enforcer`, `mode`, `uptime`, `version`, `active_bans`, `bans_by_strike`, `message` |
| `list` | Envelope: `ok`, `error`, `data` (linhas dentro de `data`) |
| `report <ip>` | Objeto: relatório de abuso versionado (`schema_version`, `ip`, `country`, `asn`, `current_ban`, `strikes`, `actions`, mais `evidence` com `--evidence`) |
| `report` | Array de resumos de ofensores (`ip`, `first_seen`, `last_seen`, `total_strikes`, `banned`, `permanent`, `country`, `asn`) |
| `watch` | NDJSON: um objeto de evento por linha |
| `doctor` | Objeto: `checks` (`name`, `status`, `hint`) e `summary` (`total`, `pass`, `fail`) |
| `config show` | Objeto: `config`, `policy` (valores efetivos, segredos redigidos) |
| `version` | Objeto: `version`, `commit`, `build_date` |

Com `--json`, o stdout carrega apenas JSON; avisos e notas de conexão vão para
o stderr, então encadear com `jq` é sempre seguro.

### Cores

Saída colorida/estilizada só é habilitada quando todas estas condições valem:
o stdout é um terminal interativo, a variável de ambiente
[`NO_COLOR`](https://no-color.org) não está definida, e `--no-color` não foi
passado. Saída redirecionada ou encadeada por pipe é sempre texto puro, então
`ezyshield watch | grep ban` nunca vê códigos de escape.

## ezyshield init

Assistente de configuração interativo. Configura fontes de log, backends de
enforcement, provedores de IA e notificações.

```bash
sudo ezyshield init
```

Cria `/etc/ezyshield/config.yaml` e `/etc/ezyshield/policy.yaml` com
permissões seguras (0600).

O assistente percorre seções nomeadas — **Environment** (o que foi detectado
no host), **Collectors**, **Allowlist**, **Edge enforcers**, **AI analysis**,
**Policy**, **Files** e **System services** — com marcas de status `✓`/`✗`/`!`
por linha. A estilização segue as [convenções globais de cores](#cores);
saída por pipe permanece texto puro.

Ao final, imprime uma seção **Summary**:

- o que foi configurado (coletores, enforcers, IA) e o que foi pulado, com o
  motivo;
- todos os arquivos escritos (incluindo o `.env` que guarda os tokens
  secretos, modo 0600 — tokens nunca vão para o `config.yaml`);
- o modo atual (`DRY-RUN` por padrão — nada é bloqueado até você definir
  `armed: true` no `policy.yaml`);
- próximos passos numerados (`doctor`, `status`, `watch`).

O resumo complementa — nunca substitui — avisos impressos durante a execução,
como o banner destacado exibido quando a configuração do enforcer Cloudflare
é abortada.

Flags:

- `--yes` — não interativo: aceita todos os padrões e pula a detecção de CDN.
- `--config-dir <dir>` — escreve os arquivos em outro diretório; pula a
  instalação das units do systemd e o start dos serviços (os próximos passos
  passam a usar o `run` em primeiro plano).

## ezyshield run

Inicia o daemon em primeiro plano. Lê logs, toma decisões e aplica banimentos.

```bash
sudo ezyshield run
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--config` | `/etc/ezyshield/config.yaml` | caminho do config.yaml |
| `--policy` | `/etc/ezyshield/policy.yaml` | caminho do policy.yaml |
| `--db` | `/var/lib/ezyshield/ezyshield.db` | caminho do banco de dados SQLite |
| `--socket` | `/run/ezyshield/ezyshield.sock` | caminho do socket de controle |

Executa em modo dry-run por padrão (`armed: false` no policy.yaml).

## ezyshield watch

Transmite eventos de segurança ao vivo do daemon em execução: detecções,
escalonamento de strikes, banimentos, banimentos em dry-run, desbanimentos e
mudanças na allowlist. É uma visão ao vivo — para um retrato pontual dos
banimentos ativos, use `list`.

```bash
# Transmitir tudo
ezyshield watch

# Apenas banimentos e banimentos em dry-run
ezyshield watch --kind ban,dry_ban

# Apenas eventos de um endereço ou bloco CIDR
ezyshield watch --ip 203.0.113.0/24

# NDJSON: um objeto JSON por linha, para jq ou um coletor de logs
ezyshield watch --json | jq .kind
```

Flags:
- `--kind` — filtra por tipo de evento: `detection`, `record`, `notify_only`,
  `dry_ban`, `ban`, `already_banned`, `unban`, `allow` (repetível ou separado
  por vírgulas)
- `--ip` — filtra por endereço IP ou bloco CIDR
- `--socket` — caminho do socket de controle do daemon

Cada evento traz timestamp, tipo, IP e campos de contexto (score, categoria,
regra, strike, TTL, enforcer, motivo, origem). Texto de evento derivado de
linhas de log é sanitizado antes da exibição — sequências de escape ANSI e
caracteres de controle são removidos, para que conteúdo hostil de logs não
possa forjar saída no seu terminal.

Se a conexão com o daemon cair (ex.: reinício), o `watch` reconecta
automaticamente com backoff. Pressione `Ctrl-C` para sair. O daemon precisa
estar em execução (`ezyshield run` ou `sudo systemctl start ezyshield`).

## ezyshield status

Mostra o status do daemon e do enforcer.

```bash
ezyshield status

# Saída em JSON
ezyshield status --json
```

| Flag | Descrição |
|------|-----------|
| `--socket` | override do caminho do socket de controle do daemon |
| `--enforcer-socket` | override do caminho do socket do enforcer |

Saída:
- Alcançabilidade do daemon e do enforcer
- Modo (enforce / dry-run), uptime, versão
- Total de banimentos ativos e distribuição por strike

## ezyshield list

Lista os banimentos ativos (padrão) ou a allowlist.

```bash
# Banimentos ativos
ezyshield list

# Agrupado por país / por ASN
ezyshield list --by-country
ezyshield list --by-asn

# Entradas da allowlist
ezyshield list --allow

# Saída em JSON
ezyshield list --json
```

| Flag | Descrição |
|------|-----------|
| `--allow` | lista as entradas da allowlist em vez dos banimentos |
| `--by-country` | agrega os banimentos por país (requer enriquecimento GeoIP) |
| `--by-asn` | agrega os banimentos por ASN (requer enriquecimento GeoIP) |
| `--socket` | override do caminho do socket de controle |

Colunas de banimento: `IP / STRIKE / TTL / COUNTRY / ASN / REASON`.
Colunas da allowlist: `IP/CIDR / EXPIRES / REASON`.

Para o histórico por IP com evidências, use `ezyshield report`.

## ezyshield report

Gera um relatório de abuso completo para um IP ofensor a partir dos registros
do daemon: identidade e enriquecimento (país, ASN), o banimento atual, o
histórico completo de strikes com os veredictos de detecção e a trilha de
ações. Sem um IP, lista todos os ofensores registrados.

```bash
# Relatório completo de um IP (texto no terminal)
ezyshield report 203.0.113.7

# Documento markdown, pronto para anexar a uma denúncia de abuse@
ezyshield report 203.0.113.7 -o md > abuse-203.0.113.7.md

# O mesmo, incluindo trechos brutos de log que mencionam o IP como evidência
ezyshield report 203.0.113.7 --evidence -o md > abuse-203.0.113.7.md

# Legível por máquina (schema versionado, seguro para scripts)
ezyshield report 203.0.113.7 --json

# Listar todos os ofensores registrados / apenas os banidos permanentemente
ezyshield report
ezyshield report --permanent
```

Flags:
- `-o, --output` — formato de saída: `text` (padrão) ou `md` (relatório de
  abuso em markdown; requer um IP)
- `--evidence` — inclui trechos brutos de log que mencionam o IP, extraídos
  sob demanda das fontes de log configuradas no daemon (requer um IP). Fontes
  de arquivo são varridas diretamente, fontes journald via `journalctl` e
  fontes docker via o socket do Docker Engine. Os trechos são limitados
  (janela mais recente, 50 linhas por fonte) e nunca são persistidos; uma
  fonte que não pode ser lida (log rotacionado, journal vazio, socket do
  engine inacessível, container removido) degrada para uma nota explicativa
  em vez de falhar o relatório
- `--permanent` — modo de listagem: apenas ofensores com banimento ativo
  permanente
- `--limit` — máximo de linhas de strike/ação (0 = padrão do servidor, 100)
- `--no-footer` — omite o rodapé "Generated by EzyShield" da saída em
  markdown
- `--socket` — caminho do socket de controle do daemon

O relatório é somente leitura e funciona tanto em modo enforce quanto em
dry-run. Campos derivados de linhas de log (motivos, categorias) são
sanitizados antes da exibição — escapes ANSI e caracteres de controle são
removidos, e células de tabelas markdown são escapadas — para que conteúdo
hostil de logs não possa forjar saída no seu terminal nem quebrar o documento.
Os trechos de evidência são renderizados como blocos de código indentados no
markdown, então uma linha de log não consegue injetar formatação no relatório.
Timestamps são UTC (RFC 3339).

## ezyshield ban

Bane manualmente um IP ou CIDR.

```bash
# Banir usando a tabela de strikes da policy (TTL do strike 1)
sudo ezyshield ban 203.0.113.42

# Duração explícita
sudo ezyshield ban --ttl 24h --reason "abuse report" 203.0.113.42

# Banir uma sub-rede
sudo ezyshield ban 203.0.113.0/24
```

| Flag | Descrição |
|------|-----------|
| `--ttl` | duração do banimento (`5m`, `24h`, `7d`); vazio = tabela de strikes da policy |
| `--reason` | motivo em texto livre armazenado no log de auditoria |
| `--socket` | override do caminho do socket de controle |

Banimentos manuais contornam o motor de regras, **não** a allowlist — um IP na
allowlist nunca pode ser banido, manualmente ou de qualquer outra forma
(invariante de segurança: a allowlist sempre vence).

## ezyshield unban

Remove um banimento ativo.

```bash
sudo ezyshield unban 203.0.113.42

# Desbanir uma sub-rede
sudo ezyshield unban 203.0.113.0/24
```

Não apaga o histórico de auditoria. (`--socket` faz override do caminho do
socket de controle.)

## ezyshield allow

Adiciona um IP ou CIDR à allowlist de runtime.

```bash
# Adicionar IP (permanente)
sudo ezyshield allow 192.0.2.100

# Adicionar CIDR
sudo ezyshield allow 192.0.2.0/24

# Entradas temporárias
sudo ezyshield allow --for 2h --reason "vendor maintenance" 198.51.100.7
sudo ezyshield allow --until 2026-08-01T00:00:00Z 198.51.100.8
```

| Flag | Descrição |
|------|-----------|
| `--for` | expiração relativa (ex.: `2h`, `7d`); mutuamente exclusiva com `--until` |
| `--until` | expiração absoluta (timestamp RFC 3339) |
| `--reason` | motivo em texto livre armazenado com a entrada |
| `--socket` | override do caminho do socket de controle |

A allowlist é verificada primeiro. Nenhuma regra pode banir um IP que está na
allowlist.

## ezyshield doctor

Valida a configuração, as permissões e as fontes de log.

```bash
sudo ezyshield doctor
```

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--config-dir` | `/etc/ezyshield` | diretório de configuração a verificar |

Verificações:
- config.yaml / policy.yaml existem, fazem parse e têm permissões/dono seguros
- binário `nft` presente
- journald legível
- socket do enforcer alcançável
- socket do docker presente (quando coletores Docker estão configurados)
- permissões do arquivo de segredos `.env`

Para exercitar de verdade os enforcers e os canais de notificação, use
`ezyshield test enforcer` e `ezyshield test notifier`.

## ezyshield config

Inspecionar e validar a configuração.

### ezyshield config show

Renderiza a configuração efetiva — após parsing, validação estrita e defaults — em YAML, ou JSON com `--json`. Valores de segredos nunca aparecem na saída: campos de credencial guardam referências `env:VARNAME` por design, e valores de headers de webhook (que podem conter tokens crus) são exibidos como `<redacted>`.

```bash
ezyshield config show

# Saída em JSON
ezyshield config show --json

# Arquivos em locais não padrão
ezyshield config show --config ./config.yaml --policy ./policy.yaml
```

Códigos de saída: `0` renderizado, `1` configuração inválida, `2` arquivo não encontrado / ilegível.

### ezyshield config validate

Valida `config.yaml` e `policy.yaml` sem iniciar o daemon: parsing YAML estrito, restrições de campos, monotonicidade da tabela de strikes, CIDRs da allowlist e avisos para caminhos de log ilegíveis ou variáveis de ambiente não definidas.

```bash
ezyshield config validate

# Arquivos em locais não padrão
ezyshield config validate --config ./config.yaml --policy ./policy.yaml
```

O comando de nível superior `ezyshield validate` é mantido como alias e se comporta de forma idêntica.

Códigos de saída: `0` válido (pode ter avisos), `1` erros encontrados, `2` arquivo não encontrado / ilegível.

### ezyshield config enforcer `<name>`

Wizard interativo para adicionar ou reconfigurar um enforcer em uma instalação existente — os mesmos prompts e a mesma validação seca de token do wizard de init, sem regenerar mais nada.

```bash
sudo ezyshield config enforcer cloudflare
```

- A escrita é atômica (arquivo temporário + rename); o arquivo anterior é mantido como `config.yaml.bak` e a configuração mesclada é revalidada antes de qualquer coisa tocar o disco. Comentários não são preservados — recupere-os do `.bak` se necessário.
- Tokens secretos vão para o arquivo `.env` ao lado do `config.yaml` (modo 0600), nunca para o `config.yaml` em si (`api_token: env:CLOUDFLARE_API_TOKEN`).
- Em caso de sucesso, o comando imprime as chaves alteradas e os próximos passos (`config validate`, reiniciar o daemon). Se o wizard for abortado, nada é escrito.

Nomes disponíveis: `cloudflare`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config notifier `<name>`

Wizard interativo para adicionar, reconfigurar ou remover um canal de notificação em uma instalação existente.

```bash
sudo ezyshield config notifier telegram
sudo ezyshield config notifier email
sudo ezyshield config notifier slack
sudo ezyshield config notifier discord
sudo ezyshield config notifier webhook
```

- Cada canal pergunta suas próprias configurações (telegram: chat IDs; email: from/to/host SMTP/porta/TLS/usuário; slack: override opcional de canal; webhook: header de autenticação opcional) mais um filtro de severidade (`info,warn,critical`; vazio = todas).
- Valores de credencial — tokens de bot, URLs de webhook (capability URLs são segredos), senhas SMTP, valores de headers de autenticação — são lidos com entrada oculta e oferecidos de duas formas: colar o valor (armazenado no arquivo `.env` ao lado do `config.yaml`, modo 0600, mesclado sem tocar nas outras linhas) ou referenciar uma variável de ambiente que você já gerencia (ex.: via sops/vault) — nesse caso o wizard grava `env:SUA_VAR` e nunca toca o `.env`. Segredos nunca vão para o `config.yaml`; ele carrega apenas referências como `bot_token: env:TELEGRAM_BOT_TOKEN`.
- Pressionar ENTER no prompt de colagem é aceitável: um valor existente no `.env` é mantido como está; caso contrário, um placeholder é gravado para você preencher depois.
- No canal genérico `webhook`, o valor do header de autenticação também é segredo: o `config.yaml` recebe `Authorization: env:WEBHOOK_AUTH_HEADER` e o daemon resolve a referência na inicialização. Valores de header simples (sem `env:`) em configs escritas à mão continuam funcionando sem mudanças.
- Reconfigurar substitui a entrada daquele canal; os ajustes compartilhados (`rate_limit_per_minute`, `dedup_window_sec`) e os outros canais são preservados. Para desabilitar um canal, responda `n` no prompt de configuração: o wizard então oferece remover a entrada existente (default não). Recusar deixa o arquivo intocado.
- A semântica de escrita é a mesma dos outros wizards: escrita atômica, `config.yaml.bak`, revalidação antes de salvar e resumo das chaves alteradas em caso de sucesso. Verifique a entrega depois com o comando de teste de notificação mostrado nos próximos passos.

Nomes disponíveis: `telegram`, `email`, `slack`, `discord`, `webhook`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config ai `<provider>`

Wizard interativo para configurar (ou trocar) o provedor de IA em uma instalação existente — os mesmos prompts de modelo e chave de API do wizard de init, sem regenerar mais nada.

```bash
sudo ezyshield config ai anthropic
sudo ezyshield config ai openai
sudo ezyshield config ai ollama
```

- A chave de API é lida com entrada oculta e oferecida de duas formas: colar a chave (armazenada no arquivo `.env` ao lado do `config.yaml`, modo 0600, mesclada sem tocar nas outras linhas) ou referenciar uma variável de ambiente que você já gerencia (ex.: via sops/vault) — nesse caso o wizard grava `api_key: env:SUA_VAR` e nunca toca o `.env`. Chaves nunca vão para o `config.yaml`.
- Pressionar ENTER no prompt de colagem é aceitável: uma chave existente no `.env` é mantida como está; caso contrário, um placeholder é gravado para você preencher depois. `ollama` roda localmente e não tem chave.
- Reconfigurar substitui os campos do provedor (`provider`, `model`, `api_key`) mas preserva seus ajustes (`ambiguous_band`, `token_budget_daily`). A semântica de escrita é a mesma do `config enforcer`: escrita atômica, `config.yaml.bak`, revalidação antes de salvar.

Provedores disponíveis: `anthropic`, `openai`, `ollama`.

Códigos de saída: `0` salvo, `1` falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config collector `<name>`

Wizard interativo para adicionar, reconfigurar ou remover um coletor de logs em uma instalação existente — os mesmos prompts que o wizard de init executa para aquela fonte, sem regenerar mais nada.

```bash
sudo ezyshield config collector sshd
sudo ezyshield config collector nginx
sudo ezyshield config collector apache
```

- `sshd` gerencia o coletor journald (confirmação e, opcionalmente, troca da unidade systemd). Nomes de servidores web (`nginx`, `apache`, `traefik`, `caddy`) perguntam primeiro a fonte de log: `file` (caminho do access-log no host, com default sugerido por servidor) ou `docker` (nome do container, lendo o stdout dele).
- Reconfigurar substitui a entrada existente daquela fonte (identificada pelo parser nos servidores web e pela unidade SSH no `sshd`) — o wizard nunca acrescenta duplicatas. Configurações com várias fontes para o mesmo servidor (ex.: dois logs de vhost do nginx) são editadas diretamente no `config.yaml`.
- Para desabilitar uma fonte, responda `n` no prompt de configuração: o wizard então oferece remover a entrada existente (default não). Recusar deixa o arquivo intocado.
- Coletores não carregam segredos; tudo fica no `config.yaml`. A semântica de escrita é a mesma dos outros wizards: escrita atômica, `config.yaml.bak`, revalidação antes de salvar e resumo das chaves alteradas em caso de sucesso.

Nomes disponíveis: `sshd`, `nginx`, `apache`, `traefik`, `caddy`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config enrich `maxmind`

Wizard interativo para configurar (ou remover) o enriquecimento GeoIP/ASN com
os bancos gratuitos MaxMind GeoLite2 — o fluxo que habilita `block_countries` /
`block_asns` no `policy.yaml` e as colunas de país/ASN em `list` e `report`.

```bash
sudo ezyshield config enrich maxmind
```

- Pergunta os dois caminhos dos bancos (defaults em `/var/lib/ezyshield/`) e se
  o daemon deve mantê-los atualizados (`auto_update`, default sim).
- Com `auto_update` ligado, o wizard pede sua license key da MaxMind
  ([cadastro gratuito GeoLite2](https://www.maxmind.com/en/geolite2/signup))
  pelo prompt padrão de segredos: cole a chave (guardada no `.env` ao lado do
  `config.yaml`, modo 0600) ou referencie uma variável de ambiente que você já
  gerencia — o `config.yaml` só carrega `license_key: env:MAXMIND_LICENSE_KEY`.
  No próximo start do daemon os bancos são baixados automaticamente se
  estiverem ausentes, e depois atualizados semanalmente.
- Com `auto_update` desligado nenhuma chave é necessária: baixe você mesmo
  `GeoLite2-Country.mmdb` e `GeoLite2-ASN.mmdb` da sua conta MaxMind e coloque
  nos caminhos configurados. Arquivos ausentes não são erro — o daemon roda com
  enriquecimento vazio até eles aparecerem.
- Para desabilitar o enriquecimento, responda `n` no prompt de configuração: o
  wizard então oferece remover a seção `enrich:` existente (default não).
- A semântica de escrita é a mesma dos outros wizards: escrita atômica,
  `config.yaml.bak`, revalidação antes de salvar e resumo das chaves alteradas.

Nomes disponíveis: `maxmind`.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

## ezyshield update

Autoatualiza os binários a partir do GitHub Releases (com verificação de
checksum).

```bash
# Verificar se existe uma release mais nova
sudo ezyshield update --check

# Atualizar para a última versão estável
sudo ezyshield update

# Atualizar/reverter para uma versão específica
sudo ezyshield update --version v0.1.0
```

Se você instalou via apt/dnf, prefira o gerenciador de pacotes (veja o guia de
instalação).

## ezyshield dashboard

Serve o dashboard web restrito ao localhost. Referência completa
(autenticação, páginas, acesso remoto): [dashboard.md](dashboard.md).

| Flag | Descrição |
|------|-----------|
| `--config` | caminho do config.yaml |
| `--addr` | override do endereço de bind (apenas loopback — endereços não loopback são recusados) |
| `--auth-db` | override do caminho do banco de autenticação |
| `--socket` | override do caminho do socket de controle do daemon |

## ezyshield completion

Gera scripts de autocompletar de shell (`bash`, `zsh`, `fish`, `powershell`):

```bash
ezyshield completion zsh > "${fpath[1]}/_ezyshield"
```

## ezyshield version

Mostra informações de versão.

```bash
ezyshield version

# Saída em JSON
ezyshield version --json
```

## ezyshield test

Executa testes de conectividade contra os componentes configurados. Como o `config`, o grupo segue o padrão `<kind> <name>`, então tipos de componente futuros se encaixam nos mesmos verbos.

### ezyshield test enforcer `<name>`

Testa a configuração e as permissões de um backend de enforcement: validade do token, acesso à conta/zones e as permissões exatas de API que o enforcer precisa — com sugestão de correção para cada verificação que falhar.

```bash
sudo ezyshield test enforcer cloudflare

# Testar todos os backends de enforcement configurados
sudo ezyshield test enforcer all
```

Nomes disponíveis: `all`, `cloudflare`, `nftables`.

Código de saída `0` se todas as verificações passarem, diferente de zero se alguma falhar.

### ezyshield test notifier `<name>`

Envia um alerta sintético para verificar um canal de notificação de ponta a ponta (segredos resolvidos do ambiente, mensagem realmente entregue).

```bash
sudo ezyshield test notifier telegram

# Testar todos os canais configurados
sudo ezyshield test notifier all
```

Nomes disponíveis: `all`, `email`, `telegram`.

Código de saída diferente de zero em caso de falha.

### Aliases descontinuados

Os verbos pré-1.0 `test-enforce <name>` e `test-notify <name>` continuam funcionando como aliases ocultos de `test enforcer` / `test notifier` — mesmas flags, mesmo comportamento — e imprimem um aviso de migração de uma linha no stderr. Serão removidos na 1.0.

## Flags globais

| Flag | Descrição |
|------|-----------|
| `--json` | Saída em JSON (veja as [convenções globais](#convenções-globais) para os formatos) |
| `--no-color` | Desabilita a saída colorida (a variável de ambiente `NO_COLOR` também é respeitada) |
| `--version` | Imprime a versão e sai |
| `-h, --help` | Mostra o texto de ajuda |

`--config` / `--policy` **não** são globais — existem nos comandos que leem
esses arquivos (`run`, `config show`, `validate`, `dashboard`), com defaults
em `/etc/ezyshield`.

## Exemplos

**Monitorar a atividade do daemon ao vivo:**

```bash
ezyshield watch --kind ban,dry_ban
```

**Exportar o histórico por IP com evidências para JSON:**

```bash
ezyshield report --json > report.json
```

**Verificar se um IP está banido no momento:**

```bash
ezyshield list --json | jq '.[] | select(.ip == "203.0.113.42")'
```

**Banir permanentemente uma sub-rede de botnet:**

```bash
sudo ezyshield ban --ttl 0 203.0.113.0/24
```

**Adicionar a rede do seu escritório à allowlist:**

```bash
sudo ezyshield allow 192.0.2.0/24
```
