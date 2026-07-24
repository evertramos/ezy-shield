---
title: Dashboard
description: Dashboard web para monitoramento e controle
order: 1
---

# Dashboard

O dashboard do EzyShield é uma pequena UI web que roda ao lado do
daemon. Ele dá ao operador uma visão via navegador do estado do
daemon, dos banimentos ativos, entradas da allowlist, do audit trail
recente e do timeline de strikes, mais controles em página para
ban / unban / allow manuais.

Ele oferece autenticação, visões ao vivo, event log, timeline de
strikes, updates ao vivo via WebSocket, forms de escrita protegidos
por CSRF, throttle de login por conta e limite de sessões por usuário.
Redação server-side e RBAC multi-usuário estão fora do escopo deste
release.

---

## Arquitetura localhost-only

O dashboard escuta **exclusivamente em endereços de loopback** —
`127.0.0.1`, `::1` ou o literal `localhost`. Qualquer outro bind
(`0.0.0.0`, interface pública, etc.) é recusado na inicialização,
tanto em `internal/dashboard.New()` quanto em `Server.Run()` — um
invariante rígido, checado duas vezes para que um erro de config não
consiga expô-lo. O dashboard só é alcançável a partir do próprio
host, e acesso remoto é, por design, uma
*preocupação do operador* — resolvida fora do daemon.

Para acesso remoto, veja o guia dedicado:
[Acesso remoto ao dashboard](../guides/dashboard-remote-access.md).
Em resumo:

- **SSH port-forward** é a opção mais simples e não exige nada
  extra no servidor.
- **Cloudflare Tunnel** ou **Tailscale** dão um caminho persistente
  sem abrir portas.
- **Não** rode o dashboard atrás de um contêiner `--network=host`
  que publique em uma interface pública, e **não** coloque
  `0.0.0.0` no config — a guarda vai recusar a subida.

---

## Instalação e primeira execução

Nada de especial — o dashboard vem no mesmo binário. O bootstrap da
primeira execução acontece no primeiríssimo `ezyshield dashboard`:

1. Gera uma senha aleatória (18 bytes aleatórios → 24 caracteres
   base64 URL-safe).
2. Armazena o hash PBKDF2-SHA256 (600 000 iterações, sal de 16 bytes
   por hash) em `<data_dir>/dashboard.db` (modo `0600`).
3. Imprime a senha em claro **uma única vez** no stderr:

   ```
   ======================================================================
   EzyShield dashboard: admin account created.
     Username: admin
     Password: 2yQ7c1p...
   STORE THIS PASSWORD NOW — it will not be shown again.
   To rotate the password, delete the auth DB and restart:
     rm /var/lib/ezyshield/dashboard.db
   ======================================================================
   ```

Em um terminal interativo, a senha em claro nunca toca o disco. Se
você perder a mensagem, apague o `dashboard.db` e reinicie — uma
conta nova será gerada.

**stderr não-interativo (systemd, Docker, cron).** Quando o stderr não
é um terminal — o caso comum no caminho de instalação documentado — o
banner acima não é impresso, porque seria capturado literalmente pelo
journald ou pelo `docker logs`. Em vez disso, a senha em claro é
gravada uma vez em `<data_dir>/dashboard.first-run-password` (modo
`0600`), e apenas o caminho do arquivo é impresso no stderr:

```
EzyShield dashboard: admin account created (username: admin).
stderr is not a terminal — the initial password was written to:
  /var/lib/ezyshield/dashboard.first-run-password (mode 0600)
Read it once and remove it:
  sudo cat /var/lib/ezyshield/dashboard.first-run-password && sudo rm /var/lib/ezyshield/dashboard.first-run-password
```

Leia o arquivo uma vez e apague-o — ele não é removido
automaticamente.

---

## Configuração

O dashboard é opt-in via o bloco `dashboard:` no `config.yaml`:

```yaml
data_dir: /var/lib/ezyshield

# Socket de controle do daemon — reaproveitado pelos verbos da CLI
# (status, ban, list, ...) e pelo dashboard quando precisa de dados
# em tempo real. Padrão: /run/ezyshield/ezyshield.sock.
socket_path: /run/ezyshield/ezyshield.sock

dashboard:
  # Endereço de bind. Precisa resolver para um endereço de loopback;
  # qualquer outra coisa é recusada no start.
  addr: 127.0.0.1:9090

  # Arquivo SQLite com o hash da credencial admin. Opcional; o padrão
  # é <data_dir>/dashboard.db.
  auth_db_path: /var/lib/ezyshield/dashboard.db
```

Flags da CLI sobrescrevem valores do config:

```bash
ezyshield dashboard \
  --addr 127.0.0.1:9091 \
  --auth-db /tmp/auth.db \
  --socket /run/ezyshield/ezyshield.sock
```

Se o `config.yaml` estiver ausente, o dashboard cai para
`127.0.0.1:9090`, `/var/lib/ezyshield/dashboard.db` e o socket padrão
do daemon — assim o operador consegue experimentar a UI antes mesmo do
daemon estar totalmente inicializado. Quando o socket do daemon não
responde, o dashboard continua renderizando: cada página mostra um
banner "Daemon offline" no lugar dos dados ao vivo.

---

## Páginas e funcionalidades

| Método | Path                     | Auth        | Notas                                                          |
|--------|--------------------------|-------------|----------------------------------------------------------------|
| GET    | `/login`                 | dispensada  | Formulário de login                                            |
| POST   | `/login`                 | dispensada  | Submit do form; grava cookie de sessão no sucesso              |
| POST   | `/logout`                | dispensada  | Limpa o cookie de sessão                                       |
| GET    | `/`                      | obrigatória | Redireciona sessões autenticadas para `/dashboard`             |
| GET    | `/dashboard`             | obrigatória | Overview: estado do daemon, modo, uptime, versão, contagem de bans ativos, distribuição por strike |
| GET    | `/dashboard/bans`        | obrigatória | Tabela de bans ativos com botão de unban por linha + form de ban manual |
| GET    | `/dashboard/allowlist`   | obrigatória | Tabela de entradas da allowlist + form de adicionar entrada    |
| GET    | `/dashboard/events`      | obrigatória | Tabela das últimas 100 linhas de `audit_log`; atualiza em tempo real via WebSocket |
| GET    | `/dashboard/timeline`    | obrigatória | Escada de 5 strikes por IP reconstruída de `list` + `events`   |
| GET    | `/dashboard/ws`          | obrigatória | Upgrade para WebSocket; empurra envelopes `audit` / `refresh`  |
| POST   | `/dashboard/ban`         | obrigatória | Ação de ban manual; redireciona para `/dashboard/bans`         |
| POST   | `/dashboard/unban`       | obrigatória | Ação de unban manual; redireciona para `/dashboard/bans`       |
| POST   | `/dashboard/allow`       | obrigatória | Ação de adicionar à allowlist; redireciona para `/dashboard/allowlist` |

Requests não autenticados em qualquer rota protegida recebem
`303 See Other` para `/login`.

### Layout e UI

- Nav superior sticky com sublinhado indicando a página ativa.
- Layout responsivo: uma coluna em telas estreitas, duas colunas
  para bans/allowlist no desktop. Tabelas ganham scroll horizontal
  automaticamente em mobile.
- Light e dark mode via `prefers-color-scheme` (sem toggle — quem
  decide é o navegador).
- Banners de sucesso e erro somem sozinhos após 5 s. O aviso
  persistente "daemon offline" **não** é dispensado.

### Flash codes

Toda ação de escrita devolve `303` para a página de origem com um
flash code em query-string (`ok=…` ou `err=…`). Só os códigos abaixo
são renderizados; qualquer outra coisa é silenciosamente ignorada
para que URLs forjadas não injetem strings arbitrárias na UI.

| Flash code       | Significado                                                     |
|------------------|-----------------------------------------------------------------|
| `ban-queued`     | Ban aceito pelo daemon                                          |
| `unban-queued`   | Unban aceito pelo daemon                                        |
| `allow-added`    | Entrada de allowlist aceita pelo daemon                         |
| `missing-ip`     | O campo `ip` veio vazio                                         |
| `invalid-ip`     | O campo `ip` não passou no parser `netip` (IP ou CIDR)          |
| `bad-form`       | Submit malformado                                               |
| `daemon-error`   | Daemon acessível mas devolveu resposta não-OK                   |
| `daemon-offline` | Socket unix do daemon não aceitou a conexão                     |

### Updates ao vivo (`/dashboard/ws`)

Toda página abre um WebSocket em `/dashboard/ws` via um script pequeno.
O endpoint passa pelo mesmo `requireAuth` das demais rotas: um upgrade
sem sessão vira `303 See Other` para `/login`.

O dashboard usa um **event bus baseado em polling** em vez de push do
daemon: a cada 3 segundos ele chama a RPC `events`, faz diff pelo
maior `audit_log.id` já visto, e distribui as linhas novas para cada
cliente conectado. É uma troca deliberada — latência sub-segundo por
uma superfície bem menor: nada muda na API de controle do daemon, não
há reader long-lived no socket e o daemon não guarda memória de
subscribers.

Envelope na rede (JSON, sempre frames de texto UTF-8):

```json
{"type": "hello"}
{"type": "audit",   "entry": {"id": 42, "recorded_at": "2026-07-08T02:15:00Z", "op": "ban", "ip": "203.0.113.7", "ttl_seconds": 300, "strike": 1, "reason": "sshd"}}
{"type": "refresh"}
```

Quando um ciclo de poll traz mais de 10 eventos, o bus colapsa a
rajada em um único `refresh` e o navegador recarrega a página. Esse
limite mais a cadência de 3 s mantêm a taxa de mensagens por cliente
baixa, sem uma rajada ilimitada de frames `audit` individuais.

A reconexão fica com o helper `EzyLive` embutido no layout: back-off
exponencial começando em 1 s e limitado a 30 s, com um "live dot"
no header que fica verde quando o socket está aberto.

### `/dashboard/events`

Tabela server-rendered com as últimas 100 linhas do `audit_log`
(mais novas primeiro), schema idêntico ao objeto `entry` acima. O
script da página escuta `EzyLive.on('audit', …)` e insere linhas
novas no topo sem recarregar, deduplicando por `data-audit-id`. O
DOM é limitado a 100 linhas para uma aba de longa duração não
crescer sem controle.

### `/dashboard/timeline`

Um card por IP atualmente banido com a escada de 5 strikes
reconstruída do audit trail recente:

- Cada step é um nível de strike (1 → 5).
- Steps atingidos ficam destacados; o tier atual fica contornado.
- Timestamps e reasons vêm direto das linhas do `audit_log`.
- Quando a janela de audit foi truncada antes de uma escalação
  anterior, o step ainda aparece como atingido (a linha em
  `bans_active` é a fonte da verdade) mas sem timestamp.

Read-only — não tem forms.

---

## Modelo de segurança

### Autenticação

- Senhas são hasheadas com **PBKDF2-SHA256, 600 000 iterações**, com
  sal aleatório por hash de 16 bytes. Verificação em tempo constante.
- No login, o caminho de "usuário desconhecido" roda `verifyPassword`
  contra um hash isca do lado do servidor, então o tempo de resposta
  não distingue conta existente de conta inexistente (CWE-208).
- Cookies de sessão: nome `ezyshield_dashboard`, token hex de 32
  bytes do `crypto/rand` (256 bits de entropia), `HttpOnly`,
  `Secure`, `SameSite=Strict`, expiração deslizante de 30 minutos
  ociosos, **apenas em memória** — reiniciar o daemon força novo
  login.
- O flag `Secure` é setado mesmo no deploy padrão em HTTP loopback:
  navegadores modernos tratam `http://localhost` como contexto
  seguro e entregam o cookie, e um reverse proxy com TLS na frente
  ganha a recusa do navegador em downgrade para plaintext.

### Proteção CSRF

- Toda sessão carrega um token CSRF independente de 32 bytes, gerado
  pelo `crypto/rand` no login e guardado na entrada de sessão.
- Todo form POST server-rendered embute o token num input escondido
  `csrf_token`, incluindo logout e os botões Unban por linha.
- Todos os handlers POST validam o token em **tempo constante** via
  `crypto/subtle.ConstantTimeCompare` antes de tocar o socket do
  daemon. Token ausente/errado devolve `403 Forbidden` sem side
  effect.
- Um cookie roubado sozinho não é suficiente para montar CSRF, e o
  `SameSite=Strict` bloqueia o navegador de mandar o cookie em POST
  cross-site.

### Rate limit de login

- Falhas de login são contadas por conta (username), não por IP de
  origem: no bind de loopback todos os clientes colapsam para
  `127.0.0.1`, e um atacante remoto rotacionando túneis burlaria um
  limite por IP.
- **5 tentativas falhas dentro de uma janela deslizante de 60 s**
  disparam um **lockout de 60 s**. Durante o lockout o handler de
  login devolve `429 Too Many Requests` com um banner fixo, sem
  consultar o store — nenhum PBKDF2 é gasto em brute-force.
- Login bem-sucedido zera a contagem imediatamente.
- Contador só em memória; reiniciar o daemon zera todo lockout — o
  que é intencional dado o escopo single-node.

### Gestão de sessão

- O store limita a **3 sessões ativas por conta**. O quarto login
  evita silenciosamente o slot mais antigo, então um cookie roubado
  tem vida útil limitada e uma máquina compartilhada não acumula
  sessões abandonadas.
- O limite é por usuário: a sessão da `alice` não é afetada quando
  o `bob` estoura o limite dele.
- Qualquer request autenticado desliza a expiração para 30 minutos
  ociosos.

### Validação de entrada

- Os handlers POST de ban / unban / allow parseiam o campo `ip` com
  `netip.ParsePrefix` (com fallback para `netip.ParseAddr` → /32 ou
  /128) *antes* de qualquer RPC — hostnames, strings gigantes e
  caracteres inválidos são recusados na borda do dashboard.
- Reasons vindos do operador são prefixados com `dashboard:admin`
  para que o `audit_log` distinga escritas do dashboard dos verbos
  da CLI. Reason vazio produz o tag puro; reason preenchido produz
  `dashboard:admin: <texto>`.
- Toda string do operador é renderizada via `html/template`, que
  auto-escapa na saída — nenhum `fmt.Sprintf`-into-HTML nos
  templates.

### Permissões do DB de auth

- Diretório pai: `0700`.
- Arquivo SQLite: `chmod 0600` após aplicar o schema.

### RPC e tratamento de offline

- Chamadas ao daemon partindo do dashboard rodam com **timeout de
  contexto de 2 segundos**, então um daemon travado não trava o
  navegador.
- Cada página e cada handler de escrita distingue
  `daemon.ErrDaemonUnreachable` de erro do daemon, renderizando
  banner de offline (nas leituras) ou flash code `daemon-offline`
  (nas escritas) no lugar de um erro cru de dial.

### Segurança do WebSocket

- O upgrade passa pelo mesmo middleware `requireAuth` de todas as
  outras rotas `/dashboard` — uma aba sem autenticação vira
  `303 See Other` para `/login`.
- A checagem de same-origin é feita pela biblioteca no handshake.
- Nem segredo nem linha crua de log atravessa o socket; só linhas
  de `audit_log` que o daemon já escreveu via INSERTs parametrizados.

---

## Solução de problemas

**Banner "Daemon is offline" em todas as páginas.** O dashboard não
conseguiu acessar o socket de controle do daemon. Confirme que o
daemon está rodando (`systemctl status ezyshield` ou `ezyshield run`
num shell), que `socket_path` no `config.yaml` bate com o que o
daemon usa, e que o usuário do dashboard está no grupo `ezyshield`
(o socket é modo `0660`).

**Perdi a senha admin.** Apague o DB de auth e reinicie o dashboard:

```bash
rm /var/lib/ezyshield/dashboard.db
ezyshield dashboard
```

O próximo start regenera uma conta admin nova e imprime a senha.
Todas as sessões existentes ficam inválidas. Faça isso no servidor,
não pela UI — se você foi trancado fora da UI, precisa de shell
mesmo.

**"Too many failed attempts" no login.** A conta está no lockout de
60 s após 5 senhas erradas. Espere 60 s. Se o lockout continuar
disparando sem motivo, reinicie o processo do dashboard para zerar
o contador em memória.

**Sessão expirou / fui deslogado.** Sessões são em memória e
deslizam a expiração conforme atividade. Se você fechou a aba e
reabriu 45 min depois, a sessão pode ter expirado (30 min ocioso).
Se você entrou em outra máquina e agora é a 4ª sessão, a mais antiga
foi evita — logue de novo neste navegador.

**Timeline mostra steps sem timestamp.** O audit trail só guarda a
janela recente (últimas 500 linhas para reconstrução do timeline).
Se um IP escalou antes dessa janela, o tier atual ainda aparece como
atingido pelo `bans_active`, mas o timestamp fica em branco. Isso é
o comportamento esperado, não é bug.

**"Forbidden" (403) depois de submeter um form.** Quase sempre é
CSRF mismatch. A causa provável é uma aba antiga de antes do login
(CSRF stale), um script/bot que raspou o form e postou depois, ou
um proxy tirando campos do form. Recarregue a página para pegar um
token novo e tente de novo.
