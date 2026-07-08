---
title: Começando
description: Guia de início rápido
order: 1
---

# Guia de Início Rápido — EzyShield

> ⚠️ Projeto em pré-alpha. Use em modo dry-run e reporte bugs via issues.
> English version: [docs/QUICKSTART.md](QUICKSTART.md)

---

## 1. Requisitos

| Requisito | Versão mínima |
|-----------|---------------|
| Go        | 1.24+         |
| Linux     | kernel 4.x+   |
| nftables  | 0.9+          |

Verifique:

```bash
go version        # go1.24 ou superior
uname -s          # Linux
nft --version     # nftables v0.9+
```

---

## 2. Instalação (build from source)

```bash
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
go build -o ezyshield ./cmd/ezyshield
sudo mv ezyshield /usr/local/bin/
```

Confirme a instalação:

```bash
ezyshield version
```

---

## 3. Setup inicial

### `ezyshield init`

Executa o wizard interativo: detecta o ambiente, grava arquivos de configuração, instala units systemd e inicia o EzyShield em modo dry-run.

```bash
sudo ezyshield init
```

Isso gera:
- `/etc/ezyshield/config.yaml`
- `/etc/ezyshield/policy.yaml`
- `/etc/ezyshield/rules.yaml` (quando containers WordPress são detectados)
- `/etc/ezyshield/.env` (chave de API do AI, modo 0600)
- `/etc/systemd/system/ezyshield.service.d/env.conf` (drop-in systemd)
- `/var/lib/ezyshield/` (dados de runtime, SQLite)

> **Pré-flight (issue #5):** o wizard verifica logo no início se `config.yaml`
> ou `policy.yaml` já existem no diretório de destino (`--config-dir` ou o
> padrão `/etc/ezyshield`). Se qualquer um deles já existir, `ezyshield init`
> falha em menos de 1s — **antes** de imprimir o banner "Detecting
> environment..." — listando todos os caminhos pré-existentes num único erro
> para você removê-los de uma só vez. Para regenerar, remova os arquivos
> apontados e rode `sudo ezyshield init` de novo.

#### Chave de API do provedor de AI (issue #22)

Quando você ativa a análise por AI, o wizard apresenta uma escolha:

```
How do you want to provide the anthropic API key?
  1) Paste it here — stored in /etc/ezyshield/.env (recommended)
  2) I already have it in an env var (e.g. from sops / vault / LoadCredential)
```

**Opção 1 (recomendada para a maioria):** cole a chave diretamente. A entrada
é com eco suprimido (como o `sudo`). A chave é gravada **somente** em
`/etc/ezyshield/.env` (modo `0600 root:ezyshield`). O `config.yaml` sempre
recebe `api_key: env:ANTHROPIC_API_KEY` — o valor bruto da chave nunca toca
nenhum arquivo de configuração, log ou lista de argumentos de processo.

**Opção 2 (avançado — sops / vault / LoadCredential):** informe o nome da
variável de ambiente onde sua plataforma já expõe a chave. O wizard valida o
nome com `^[A-Za-z_][A-Za-z0-9_]*$` e rejeita qualquer entrada com formato de
segredo (proteção issue #13). O valor da chave nunca é tocado ou lido pelo
wizard.

**Modo `--yes` / não-interativo:** pula o prompt da chave. Um placeholder
(`ANTHROPIC_API_KEY=YOUR_API_KEY_HERE`) é gravado em `/etc/ezyshield/.env`.
Edite o arquivo e reinicie o daemon após o provisionamento.

Em todos os casos o wizard também cria
`/etc/systemd/system/ezyshield.service.d/env.conf` contendo:

```ini
[Service]
EnvironmentFile=-/etc/ezyshield/.env
```

Isso garante que o daemon carregue a chave mesmo em hosts com um service file
mais antigo. `systemctl daemon-reload` é executado automaticamente antes de
`enable --now`.

Nomes canônicos de variáveis de ambiente (fixos, não configuráveis pelo operador):

| Provedor    | Variável de ambiente |
|-------------|----------------------|
| `anthropic` | `ANTHROPIC_API_KEY`  |
| `openai`    | `OPENAI_API_KEY`     |
| `ollama`    | *(sem chave)*        |

### `ezyshield doctor`

Valida toda a configuração e verifica dependências:

```bash
sudo ezyshield doctor
```

Saída esperada:

```
✓ config.yaml válido
✓ policy.yaml válido
✓ rules.yaml válido
✓ nftables acessível
✓ diretório de dados gravável
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
    socket: /run/ezyshield-enforcer/enforcer.sock   # default; omit to use default path
    table: inet ezyshield
    set: blocked
```

Para ativar o enforcement local via nftables:

1. Certifique-se de que o helper privilegiado (`ezyshield-enforcer`) está rodando e escutando no socket unix configurado (padrão: `/run/ezyshield-enforcer/enforcer.sock`).
2. Adicione a seção `enforce.nftables` ao `config.yaml` (como acima).
3. Defina `armed: true` em `policy.yaml`.
4. Inicie o daemon: `ezyshield watch`.

> **Nota**: Se o socket do enforcer não existir no momento da inicialização, o daemon registra um WARN e continua operando — bans ficam armazenados no SQLite e serão aplicados quando o helper estiver disponível (reconexão automática).

### AI (análise inteligente — opcional)

```yaml
ai:
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 75]
  token_budget_daily: 500000
```

> **Importante**: Segredos (tokens, senhas) devem usar referência `env:NOME_DA_VARIAVEL`.
> Valores inline são rejeitados na carga do config. O wizard `ezyshield init` sempre
> grava `env:NOME_CANONICO` — o valor bruto da chave nunca entra no `config.yaml`.

---

## 5. Configuração — policy.yaml

Arquivo em `/etc/ezyshield/policy.yaml`. Controla comportamento de bloqueio.

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

### Strike table (escalação de banimentos)

```yaml
strikes:
  - ttl: 5m      # strike 1 — 5 minutos
  - ttl: 1h      # strike 2 — 1 hora
  - ttl: 24h     # strike 3 — 24 horas
  - ttl: 168h    # strike 4 — 7 dias
  - ttl: 0       # strike 5 — permanente
```

> **Semântica de deduplicação:** Um *strike* representa um **episódio de ataque**, não uma requisição individual. Enquanto um IP já está banido (registro ativo em `bans_active`), novas detecções são suprimidas — nenhum novo strike é gravado, nenhuma chamada RPC ao enforcer ocorre, e apenas `offenders.last_seen` é atualizado. Isso é refletido no campo `Op` da ação como `"already_banned"`. Quando o banimento expira (via `ExpireBans`), a próxima detecção avança para o próximo nível da escada normalmente. Isso torna `offenders.total_strikes` um indicador de reincidência real, não um contador bruto de requisições maliciosas.

### Thresholds (limiares de score)

```yaml
ban_threshold: 70       # score ≥ 70 → aplica strike
observe_threshold: 40   # score 40-69 → log/notifica, sem ban
max_bans_per_minute: 30 # segurança: pausa enforcement se exceder
```

---

## 6. Regras customizadas — rules.yaml

Arquivo em `/etc/ezyshield/rules.yaml`. Define regras de detecção.

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

| Campo        | Descrição                                          |
|--------------|--------------------------------------------------|
| `name`       | Identificador único da regra                      |
| `description`| Descrição legível                                 |
| `kinds`      | Tipos de evento que ativam a regra                |
| `window`     | Janela de tempo para contagem                     |
| `threshold`  | Nº de ocorrências para disparar                   |
| `score`      | Pontuação atribuída (0-100)                       |
| `category`   | Categoria (`bruteforce`, `scanner`, etc.)         |
| `field`      | Campo do evento para filtro (opcional)            |
| `value`      | Valor exato do campo (opcional)                   |
| `contains`   | Substring no campo (opcional)                     |

### Exemplo: regra customizada para bloquear scanners de API

```yaml
  - name: api_scanner
    description: "Varredura de endpoints inexistentes na API"
    kinds: [http_request]
    field: status
    value: "404"
    window: 30s
    threshold: 15
    score: 75
    category: scanner
```

> **Nota**: O arquivo custom substitui as regras padrão por completo (não há merge). Copie as regras built-in que deseja manter.

---

## 7. Notificações

### Telegram

1. Crie um bot via [@BotFather](https://t.me/BotFather) e obtenha o token.
2. Adicione o bot ao grupo/canal e obtenha o `chat_id`.
3. Exporte o token como variável de ambiente:

```bash
export EZYSHIELD_TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
```

4. Configure em `config.yaml`:

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

1. Exporte a senha SMTP:

```bash
export EZYSHIELD_SMTP_PASSWORD="sua-senha-smtp"
```

2. Configure em `config.yaml`:

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

Modos TLS disponíveis:
- `starttls` — porta 587 (padrão, recomendado)
- `tls` — porta 465 (TLS implícito)
- `none` — sem criptografia (não recomendado)

---

## 8. Testar notificações

Após configurar, valide o envio sem precisar de um evento real:

```bash
# Testar canal Telegram
sudo ezyshield test-notify telegram

# Testar canal Email
sudo ezyshield test-notify email
```

Se tudo estiver correto, você receberá uma notificação de teste no canal configurado. Em caso de erro, a saída indicará o problema (token inválido, chat_id incorreto, falha SMTP, etc.).

Use `--json` para saída estruturada:

```bash
sudo ezyshield test-notify telegram --json
```

---

## 9. Rodar o daemon

O `watch` roda o pipeline completo (collectors → detecção → decisão → enforcement
→ notificação). Enquanto `armed: false` no `policy.yaml`, ele opera em **dry-run**:
processa tudo e registra o que *seria* bloqueado, sem tocar no firewall.

```bash
# Foreground (dry-run enquanto armed: false)
sudo ezyshield watch
```

> Não existe um comando `dry-run` separado: o dry-run é o modo padrão, controlado
> por `armed` no `policy.yaml`. Valide o comportamento com `armed: false` antes de
> mudar para `armed: true`.

### Como serviço (systemd)

Units prontas acompanham o repositório em [`configs/systemd/`](../configs/systemd/):
`ezyshield.service` (daemon) e `ezyshield-enforcer.service` (helper privilegiado
com `CAP_NET_ADMIN`). Instale e ative:

```bash
sudo cp configs/systemd/ezyshield-enforcer.service /etc/systemd/system/
sudo cp configs/systemd/ezyshield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ezyshield-enforcer
sudo systemctl enable --now ezyshield
```

### Checklist antes de ativar

1. ✅ `ezyshield doctor` sem erros
2. ✅ `allowlist` com seus IPs de acesso
3. ✅ `admin_cidrs` com seu IP SSH
4. ✅ Notificações testadas com `test-notify`
5. ✅ `armed: false` para validar com dry-run primeiro
6. ⬜ Após validação, mudar para `armed: true`
