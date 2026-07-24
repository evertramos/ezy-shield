---
title: Começando
description: Guia de início rápido para instalar e rodar o EzyShield
order: 1
---

# Guia de Início Rápido — EzyShield

Coloque o EzyShield rodando no seu servidor em menos de 5 minutos.

---

## 1. Requisitos

| Requisito | Versão mínima |
|-----------|---------------|
| Linux     | kernel 4.x+   |
| nftables  | 0.9+          |

---

## 2. Instalação

### Instalação rápida (recomendado)

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

Isso baixa os binários mais recentes com checksum verificado (`ezyshield` e
`ezyshield-enforcer`), verifica checksums e instala em `/usr/local/bin/`.

Para instalar uma versão específica:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0 sh
```

### Build from source

Requer **Go 1.26+**.

```bash
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
go build -o ezyshield ./cmd/ezyshield
go build -o ezyshield-enforcer ./cmd/ezyshield-enforcer
sudo mv ezyshield ezyshield-enforcer /usr/local/bin/
```

### Verificar

```bash
ezyshield version
```

---

## 3. Setup inicial

### `ezyshield init`

Executa o wizard interativo: detecta o ambiente, grava arquivos de configuração,
instala units systemd e inicia o EzyShield em modo dry-run.

```bash
sudo ezyshield init
```

Isso cria:

- `/etc/ezyshield/config.yaml`
- `/etc/ezyshield/policy.yaml`
- `/etc/ezyshield/rules.d/` (customizações de regras via drop-in; instalações WordPress também recebem um template de tuning comentado `10-wordpress.yaml`)
- `/etc/ezyshield/.env` (chave de API do AI, modo 0600)
- `/etc/systemd/system/ezyshield.service.d/env.conf` (drop-in systemd)
- `/var/lib/ezyshield/` (dados de runtime, SQLite)

> **Dica:** Se os arquivos de config já existirem, `ezyshield init` sai
> imediatamente listando os caminhos conflitantes. Remova-os e rode novamente.

#### Chave de API do provedor de AI

Quando você ativa a análise por AI, o wizard solicita sua chave de API.
A chave é armazenada em `/etc/ezyshield/.env` (modo `0600`) — nunca em
arquivos de configuração ou logs.

Provedores suportados:

| Provedor    | Variável de ambiente |
|-------------|----------------------|
| `anthropic` | `ANTHROPIC_API_KEY`  |
| `openai`    | `OPENAI_API_KEY`     |
| `ollama`    | *(sem chave)*        |

Use `--yes` para modo não-interativo (grava um placeholder que você edita depois).

### `ezyshield doctor`

Valida a configuração e verifica dependências:

```bash
sudo ezyshield doctor
```

Saída esperada:

```
[PASS] config.yaml: exists
[PASS] config.yaml: parses
[PASS] policy.yaml: exists
[PASS] policy.yaml: parses
[PASS] nft: binary present
[PASS] journald: readable
[PASS] enforcer: socket connectivity
```

---

## 4. Configuração — config.yaml

Arquivo principal em `/etc/ezyshield/config.yaml`.

### Collectors (fontes de log)

```yaml
collectors:
  - kind: journald
    unit: sshd
  - kind: file
    path: /var/log/nginx/access.log
```

Tipos disponíveis:

- `journald` — requer campo `unit` (nome do serviço systemd)
- `file` — requer campo `path` (caminho do arquivo de log)

### Enforce (enforcement local)

```yaml
enforce:
  nftables:
    table: inet ezyshield
    set: blocked
```

O helper privilegiado (`ezyshield-enforcer`) lida com todas as escritas no
firewall via unix socket. O daemon re-sincroniza o conjunto completo de bans
para o enforcer sempre que o **daemon** reinicia, então os bans sobrevivem a
reinícios do daemon. Reiniciar apenas o helper `ezyshield-enforcer` não
dispara essa re-sincronização por si só — o conjunto de bans se atualiza no
próximo ciclo periódico de expiração de bans, ou no próximo reinício do
daemon.

### AI (opcional)

```yaml
ai:
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 75]
  token_budget_daily: 500000
```

> **Importante**: Segredos devem usar referências `env:NOME_DA_VARIAVEL`.
> Valores inline são rejeitados na carga do config.

---

## 5. Configuração — policy.yaml

Arquivo em `/etc/ezyshield/policy.yaml`. Controla o comportamento de bloqueio.

### armed (modo de operação)

```yaml
armed: false   # dry-run (padrão) — nenhum bloqueio real
# armed: true  # ativar somente após validar com 'ezyshield doctor'
```

### Allowlist

IPs e CIDRs que **nunca** serão bloqueados:

```yaml
allowlist:
  - 192.168.1.0/24
  - 10.0.0.1

admin_cidrs:
  - 203.0.113.50/32   # seu IP de acesso SSH
```

### Strike table (escalação de bans)

```yaml
strikes:
  - ttl: 5m      # strike 1 — 5 minutos
  - ttl: 1h      # strike 2 — 1 hora
  - ttl: 24h     # strike 3 — 24 horas
  - ttl: 168h    # strike 4 — 7 dias
  - ttl: 0       # strike 5 — permanente
```

Cada strike representa um **episódio de ataque**, não uma requisição individual.
Enquanto um IP já está banido, novas detecções são suprimidas até o ban expirar.

### Thresholds

```yaml
ban_threshold: 70       # score ≥ 70 → aplica strike
observe_threshold: 40   # score 40–69 → log/notifica, sem ban
max_bans_per_minute: 30 # segurança: pausa enforcement se exceder
```

---

## 6. Regras customizadas — drop-ins em rules.d

As regras de detecção são embutidas no binário e atualizam com ele. Para
ajustar ou adicionar regras, coloque um arquivo `*.yaml` em
`/etc/ezyshield/rules.d/` — as entradas fazem merge sobre as regras
embutidas por `name` e sobrevivem a updates. Guia completo:
[Customizando Regras de Detecção](../guides/rules-customization.md).

### Estrutura de uma regra

```yaml
rules:
  - name: ssh_bruteforce
    description: "Falhas de autenticação SSH repetidas"
    kinds: [ssh_fail, ssh_invalid_user]
    window: 60s
    threshold: 5
    score: 85
    category: bruteforce
```

### Campos

| Campo        | Descrição                                |
|--------------|------------------------------------------|
| `name`       | Identificador único da regra             |
| `description`| Descrição legível                        |
| `kinds`      | Tipos de evento que ativam a regra       |
| `window`     | Janela de tempo para contagem            |
| `threshold`  | Ocorrências para disparar                |
| `score`      | Pontuação atribuída (0–100)              |
| `category`   | Categoria (`bruteforce`, `scanner`, etc.) |
| `field`      | Campo do evento para filtro (opcional)   |
| `value`      | Valor exato do campo (opcional)          |
| `contains`   | Match de substring (opcional)            |

### Exemplo: bloquear scanners de API

```yaml
  - name: api_scanner
    description: "Varredura de endpoints inexistentes"
    kinds: [http_request]
    field: status
    value: "404"
    window: 30s
    threshold: 15
    score: 75
    category: scanner
```

> **Nota**: Um drop-in só toca as regras que ele nomeia — todo o resto
> continua recebendo updates do binário. Um drop-in inválido impede o daemon
> de iniciar (fail-closed). O `rules_path` legado (substituição do arquivo
> inteiro) está deprecated.

---

## 7. Notificações

### Telegram

1. Crie um bot via [@BotFather](https://t.me/BotFather) e obtenha o token.
2. Adicione o bot ao grupo/canal e obtenha o `chat_id`.
3. Configure em `config.yaml`:

```yaml
notify:
  rate_limit_per_minute: 5
  dedup_window_sec: 600

  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_BOT_TOKEN
    chat_ids:
      - "-1001234567890"
    severity: []   # vazio = todas; ou: [warn, critical]
```

### Email (SMTP)

```yaml
  email:
    from: ezyshield@seudominio.com
    to:
      - admin@seudominio.com
    host: smtp.seudominio.com
    port: 587
    username: ezyshield@seudominio.com
    password: env:EZYSHIELD_SMTP_PASSWORD
    tls: starttls   # starttls | tls | none
    severity: []
```

---

## 8. Testar notificações

Valide o envio sem precisar de um evento real:

```bash
sudo ezyshield test notifier telegram
sudo ezyshield test notifier email
```

---

## 9. Rodar o daemon

```bash
sudo ezyshield run
```

Enquanto `armed: false`, o EzyShield opera em **dry-run**: processa tudo,
registra strikes e bans simulados para que a escalada espelhe a produção
exatamente (ADR-0009), e
registra o que *seria* bloqueado, sem tocar no firewall.

### Como serviço (systemd)

```bash
sudo systemctl enable --now ezyshield-enforcer
sudo systemctl enable --now ezyshield
```

### Checklist antes de armar

1. ✅ `ezyshield doctor` — sem erros
2. ✅ `allowlist` com seus IPs de acesso
3. ✅ `admin_cidrs` com seu IP SSH
4. ✅ Notificações testadas com `test notifier`
5. ✅ Rodou em dry-run, revisou os logs
6. ⬜ Rodar `sudo ezyshield arm --for 1h` (pre-flight + janela de auto-reversão), depois `sudo ezyshield arm --keep` quando estiver confiante
