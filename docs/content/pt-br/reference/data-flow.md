---
title: Referência de Fluxo de Dados
description: Toda conexão de saída — quando, para onde, o que é enviado, e como rodar totalmente local
order: 5
---

# Referência de Fluxo de Dados

Confiar em um daemon de segurança com capacidade de root significa saber
exatamente o que ele envia, para onde e quando. Esta página lista **toda
conexão de saída que o EzyShield pode fazer**, o que cada payload contém, e a
configuração exata para rodar com **zero tráfego de saída**.

Dois fatos enquadram tudo abaixo:

- **O pipeline central é totalmente local.** Collectors, parsers, o rule
  engine, o decision engine, o enforcement via nftables, o banco SQLite e a
  trilha de auditoria rodam offline. Nenhuma funcionalidade exige conta,
  cadastro ou conexão com qualquer serviço operado pelo EzyShield — não
  existe nenhum.
- **Não há telemetria.** Sem analytics de uso, sem crash reporting, sem
  pings de atualização a partir do daemon. Toda conexão listada aqui é algo
  que **você configurou** ou um comando que **você executou**.

Cada afirmação desta página é verificável no código-fonte; a última seção
mapeia cada conexão para o arquivo que a implementa.

## Conexões do daemon em runtime (todas opt-in)

Só acontecem enquanto o daemon roda, e apenas se você habilitou o recurso.

| Conexão | Destino | Gatilho | O que é enviado | Como desabilitar |
|---|---|---|---|---|
| Verdicts de AI (Anthropic) | `api.anthropic.com` (fixo) | Um aggregate pontua na faixa ambígua — casos óbvios nunca saem do rule engine | Apenas resumo por IP: IP do atacante, janela de tempo, contadores de eventos por tipo, e metadados GeoIP/ASN se configurados. **Linhas de log cruas são excluídas por design** — sem usernames, paths ou user agents. A chave de API viaja só no header `x-api-key` | Omitir a seção `ai:` |
| Verdicts de AI (OpenAI) | `api.openai.com` (fixo) | Igual acima | Mesmo formato de payload; chave no header `Authorization` | Omitir a seção `ai:` |
| Verdicts de AI (Ollama) | `http://localhost:11434` por padrão — só sai da máquina se você apontar `endpoint` para um host remoto | Igual acima | Mesmo formato de payload; sem chave de API | Omitir a seção `ai:` |
| Enforcement de borda Cloudflare | `api.cloudflare.com` | Um ban/unban real com o daemon **armado**, mais a reconciliação periódica (`Sync`). Em dry-run (`armed: false`) nenhuma chamada ao enforcer é feita | O endereço IP banido e um comentário fixo `ezyshield`. **Sem domínios, sem nomes de regra, sem conteúdo de log.** Account ID na URL, token no header | Não configurar o enforcer `cloudflare` |
| Atualização dos bancos GeoIP/ASN | `download.maxmind.com` | Somente com uma license key da MaxMind configurada: na inicialização se um arquivo de banco estiver ausente, depois semanalmente | A license key e o nome da edição (`GeoLite2-Country` / `GeoLite2-ASN`) como parâmetros da requisição — nada sobre seu servidor ou tráfego. **As consultas em si são locais** (arquivos `.mmdb` em disco) | Não configurar license key (pular `ezyshield config enrich maxmind`) |
| Notificações — Telegram | `api.telegram.org` | Um evento notificável (ban, erro crítico), conforme seu `notify:`, após dedup/rate limiting | Campos estruturados do alerta: severidade, título, um resumo curto e a ação que disparou (operação, IP, motivo, TTL). Com limite de tamanho e escaping; **sem linhas de log cruas** | Omitir o notifier |
| Notificações — Slack / Discord / webhook | A URL de webhook que **você** configura | Igual | Mesmos campos em JSON | Omitir o notifier |
| Notificações — e-mail | O servidor SMTP que **você** configura | Igual | Mesmos campos como mensagem MIME | Omitir o notifier |

Toda requisição de saída usa HTTPS com verificação de certificado (Ollama e
SMTP vão para onde você apontar), tem timeout e honra o cancelamento no
shutdown. Uma chamada de AI que falha cai para o rule engine; uma notificação
ou atualização de banco que falha é logada e tentada depois — o pipeline de
detecção nunca bloqueia na rede.

## Conexões em tempo de comando (só enquanto você as executa)

Acontecem interativamente, nunca a partir do daemon:

- **`ezyshield update`** — contata `api.github.com` e baixa de `github.com`
  (requisições GET simples; os checksums do release são verificados antes de
  instalar). O daemon **nunca verifica atualizações sozinho**. Hosts
  air-gapped podem apontar `EZYSHIELD_UPDATE_URL` para um mirror interno —
  ou simplesmente nunca rodar o comando e atualizar pelo seu próprio mirror
  de pacotes.
- **`ezyshield init`** — consulta `https://ifconfig.me` pelo IP público do
  seu servidor (para sugerir entradas de allowlist); pode instalar o
  `nftables` pelo gerenciador de pacotes do sistema se estiver ausente; e,
  apenas se você escolher Cloudflare, verifica o token e configura a
  lista/regra WAF contra `api.cloudflare.com`.
- **`ezyshield config enforcer cloudflare` / `ezyshield test enforce
  cloudflare`** — verificação de token e checagens de conectividade contra
  `api.cloudflare.com`.

## O que nunca sai da máquina

- **Linhas de log cruas.** São parseadas e armazenadas localmente. O único
  lugar para onde viajam é o seu próprio terminal ou arquivo de relatório: a
  extração de evidências (`ezyshield report`) lê o journald via uma execução
  local de `journalctl` e os logs Docker via o socket unix local do Engine
  (`/var/run/docker.sock`). Enviar um abuse report para qualquer lugar é uma
  ação manual sua com o arquivo gerado.
- **Sua identidade e a dos seus usuários.** Hostnames, domínios dos sites,
  usernames, paths de requisição e user agents não aparecem em **nenhum**
  payload de saída. Os providers de AI recebem contadores; a Cloudflare
  recebe IPs de atacantes.
- **Segredos.** Cada credencial é enviada apenas ao seu próprio serviço,
  como mecanismo de autenticação daquele serviço. Segredos nunca aparecem em
  corpos de payload, logs ou mensagens de erro — gates de CI garantem isso
  (`internal/ai/secret_leak_test.go`, `internal/config/secret_leak_test.go`).
- **O banco de dados.** O SQLite, o histórico de strikes e a trilha de
  auditoria append-only são arquivos locais. Nada os sincroniza para lugar
  nenhum.
- **Telemetria.** Não existe — sem analytics, sem phone-home, sem crash
  reporting, sem pings de versão.

A letra miúda, com honestidade: qualquer requisição de saída implica uma
consulta DNS daquele destino pelo resolver do sistema, e os IPs de atacantes
que você bane ficam visíveis para a Cloudflare se você habilitar o
enforcement de borda — isso é o recurso funcionando como descrito.

## Superfícies apenas locais

Por completude, as interfaces que existem mas nunca aceitam ou fazem conexões
de rede além do host:

- **Plano de controle** — um socket unix (`0660`), sem listener TCP.
- **Dashboard** — escuta apenas em `127.0.0.1` e serve assets embutidos;
  suas páginas não buscam scripts ou fontes de CDN.
- **Collectors** — tail de arquivos, `journalctl` (processo local) e o
  socket unix do Docker Engine.
- **Faixas de CDN e regras de detecção** — embutidas no binário em tempo de
  build, não baixadas em runtime.

## Rodando totalmente local (zero saída)

A configuração abaixo produz um daemon que **não faz nenhuma conexão de
rede** além de entregar pacotes ao próprio firewall:

- **AI**: omita a seção `ai:` por completo — ou rode o
  [Ollama](https://ollama.com) no mesmo host (`endpoint:
  http://localhost:11434`) para ter verdicts de AI sem sair da máquina.
- **Enforcement**: configure apenas o enforcer `nftables` (pule o
  `cloudflare`). Todo o bloqueio acontece no firewall local.
- **Enriquecimento**: não configure license key da MaxMind. As decisões
  funcionam sem GeoIP; você perde o contexto de país/ASN nos relatórios e
  nos payloads de AI.
- **Notificações**: omita `notify:` (ou aponte o e-mail para um relay local
  e aceite esse salto).
- **Atualizações**: instale pelos pacotes assinados via seu próprio mirror e
  nunca rode `ezyshield update`, ou defina `EZYSHIELD_UPDATE_URL` para um
  mirror interno.

O que você abre mão, com honestidade: bloqueio na borda (atacantes chegam ao
seu firewall antes de serem descartados — mas continuam sendo descartados),
segunda opinião da AI (o rule engine determinístico é o detector primário e
continua funcionando igual), contexto GeoIP/ASN, notificações push e
atualização em um comando. A qualidade de detecção, a escada de strikes, o
anti-lockout e a trilha de auditoria não são afetados.

## Verifique você mesmo

Cada conexão acima mapeia para um arquivo de implementação:

| Conexão | Fonte |
|---|---|
| Anthropic | `internal/ai/anthropic.go` (sanitização do payload documentada no tipo `aggregatePayload`) |
| OpenAI | `internal/ai/openai.go` |
| Ollama | `internal/ai/ollama.go` |
| Enforcer Cloudflare | `internal/enforce/cloudflare.go`, `internal/enforce/cloudflare_lists.go` |
| Updater MaxMind | `internal/enrich/updater.go` |
| Telegram / Slack / Discord / webhook / e-mail | `internal/notify/` |
| `ezyshield update` | `internal/update/client.go`, `cmd/ezyshield/update.go` |
| Consulta de IP público do `init` | `cmd/ezyshield/init.go` |
| Chamadas Cloudflare do wizard/test | `cmd/ezyshield/init_cdn.go`, `cmd/ezyshield/testenforce.go` |
| Extração local de evidências | `internal/daemon/evidence_ondemand.go` |

Uma auditoria rápida de que a lista está completa:

```bash
grep -rn "https://" --include="*.go" internal/ cmd/ | grep -v _test
```

Se um release futuro adicionar uma conexão de saída, esta página deve mudar
no mesmo pull request — trate qualquer divergência como bug e reporte.
