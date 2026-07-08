# Dashboard

O dashboard do EzyShield é uma pequena UI web que roda ao lado do daemon e
oferece aos operadores uma visão via navegador do estado do daemon, banimentos
ativos, histórico de strikes, allowlist e logs.

**Status:** Fase 2 — autenticação, páginas de status, banimentos ativos
e allowlist, mais ações de ban / unban / allow via POST. O log-tail em
tempo real via WebSocket entra na Fase 3 (issue #56).

---

## Arquitetura localhost-only

O dashboard escuta **exclusivamente em endereços de loopback** — `127.0.0.1`,
`::1` ou o literal `localhost`. Qualquer outro bind (`0.0.0.0`, interface
pública, etc.) é recusado na inicialização, tanto em
`internal/dashboard.New()` quanto em `Server.Run()`.

Essa é uma regra dura do `AGENTS.md §2` (“No new listeners on 0.0.0.0”) e do
`docs/SECURITY-REVIEW.md §6` (superfícies de controle). Portanto o dashboard
só é alcançável a partir do próprio host, e acesso remoto é, por design, uma
*preocupação do operador* — resolvida fora do daemon.

### Acesso remoto — padrões recomendados

Ambos os padrões terminam fora do `ezyshield`; o processo do dashboard
continua vendo apenas conexões locais.

- **SSH port-forward (o mais simples, sem serviço extra).** Na sua estação:

  ```bash
  ssh -L 9090:127.0.0.1:9090 operador@servidor.exemplo.com
  # depois abra http://localhost:9090 no navegador
  ```

- **Cloudflare Tunnel (persistente, sem portas abertas).** O `cloudflared`
  roda no servidor, abre um túnel de saída e publica o dashboard atrás do
  Cloudflare Access. O dashboard continua ligado apenas em `127.0.0.1` no
  servidor; só o `cloudflared` conhece o Cloudflare.

**Não** rode o dashboard atrás de um contêiner `--network=host` que
encaminhe para uma interface pública, e **não** coloque `0.0.0.0` no config —
a guarda vai recusar a subida.

---

## Bootstrap na primeira execução

Na primeiríssima execução de `ezyshield dashboard`, se não houver conta admin
no armazenamento de autenticação, o EzyShield:

1. gera uma senha aleatória (18 bytes aleatórios → 24 caracteres base64
   URL-safe),
2. armazena o hash PBKDF2-SHA256 (600 000 iterações, sal de 16 bytes por
   usuário) em `<data_dir>/dashboard.db` (modo `0600`),
3. imprime a senha em claro **uma única vez** no stderr.

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

A senha em claro nunca toca o disco. Se você perder a mensagem, apague o
`dashboard.db` e reinicie o `ezyshield dashboard` — uma conta nova será
gerada.

---

## Configuração

O dashboard é opt-in via o bloco `dashboard:` no `config.yaml`:

```yaml
data_dir: /var/lib/ezyshield

# Socket de controle do daemon — reaproveitado pelos verbos da CLI
# (status, ban, list, ...) e pelo dashboard quando precisa de dados
# em tempo real. O padrão é /run/ezyshield/ezyshield.sock.
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
`127.0.0.1:9090`, `/var/lib/ezyshield/dashboard.db` e o socket padrão do
daemon — assim o operador consegue experimentar a UI antes mesmo do
daemon estar totalmente inicializado. Quando o socket do daemon não
responde, o dashboard continua renderizando: cada página mostra um
banner "Daemon offline" no lugar dos dados ao vivo.

---

## Rotas

| Método | Path                     | Auth        | Notas                                                          |
|--------|--------------------------|-------------|----------------------------------------------------------------|
| GET    | `/login`                 | dispensada  | Formulário de login                                            |
| POST   | `/login`                 | dispensada  | Submit do form; grava cookie de sessão no sucesso              |
| POST   | `/logout`                | dispensada  | Limpa o cookie de sessão                                       |
| GET    | `/`                      | obrigatória | Redireciona sessões autenticadas para `/dashboard`             |
| GET    | `/dashboard`             | obrigatória | Overview de status: estado do daemon, modo, uptime, versão, contagem de bans ativos, distribuição por strike |
| GET    | `/dashboard/bans`        | obrigatória | Tabela de bans ativos com botão de unban por linha + form de ban manual |
| GET    | `/dashboard/allowlist`   | obrigatória | Tabela de entradas da allowlist + form de adicionar entrada    |
| POST   | `/dashboard/ban`         | obrigatória | Ação de ban manual; redireciona para `/dashboard/bans`         |
| POST   | `/dashboard/unban`       | obrigatória | Ação de unban manual; redireciona para `/dashboard/bans`       |
| POST   | `/dashboard/allow`       | obrigatória | Ação de adicionar à allowlist; redireciona para `/dashboard/allowlist` |

Requests não autenticados em qualquer rota protegida recebem `303 See
Other` para `/login`.

Toda ação de escrita devolve `303` para a página de origem com um flash
code em query-string (`ok=…` ou `err=…`). Só os códigos abaixo são
renderizados; qualquer outra coisa é silenciosamente ignorada para que
URLs forjadas não injetem strings arbitrárias na UI.

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

Cookies de sessão:
- nome `ezyshield_dashboard`,
- token hex de 32 bytes do `crypto/rand` (256 bits de entropia),
- `HttpOnly`, `Secure`, `SameSite=Strict`,
- expiração deslizante de 30 minutos ociosos,
- guardados **apenas em memória** — reiniciar o daemon força novo login.

O flag `Secure` é setado mesmo no deploy padrão em HTTP loopback:
navegadores modernos tratam `http://localhost` como contexto seguro e
entregam o cookie normalmente, ao mesmo tempo em que operadores que
colocam TLS na frente (reverse proxy, Cloudflare Tunnel) ganham a
recusa do navegador em downgrade para plaintext.

---

## Postura de segurança

- **Bind guard:** só loopback, verificado duas vezes (construção e start).
- **Armazenamento de senha:** PBKDF2-SHA256, 600 000 iterações, sal
  aleatório por hash, comparação em tempo constante.
- **Guarda contra enumeração:** o handler de login roda o mesmo trabalho
  PBKDF2 contra um hash isca no caminho de "usuário inexistente", então
  requests com usuário desconhecido e senha errada ficam
  indistinguíveis em wall-clock (CWE-208).
- **Session store:** em memória, protegido por mutex, token opaco, expiração
  deslizante.
- **Templates:** renderizados com `html/template`; toda string vinda do
  operador — reason das ações, IP ecoado em erro — passa pelo auto-escape.
- **Validação de entrada nas ações de escrita:** o campo `ip` é parseado
  com `netip.ParsePrefix` (com fallback para `netip.ParseAddr`) *antes*
  de qualquer RPC ao daemon, então hostnames, strings gigantes e
  caracteres inválidos são recusados na borda do dashboard
  (`SECURITY-REVIEW.md §1`).
- **Permissões do DB de auth:** diretório pai criado com `0700`, arquivo em
  `chmod 0600` após aplicar o schema.
- **Budget de RPC:** chamadas ao daemon partindo do dashboard rodam com
  timeout de contexto de 2 segundos, então um daemon travado não trava
  o navegador.
- **Tratamento de daemon offline:** cada página e cada handler de escrita
  distingue `daemon.ErrDaemonUnreachable` de erro do daemon, renderizando
  banner de offline (nas leituras) ou flash code `daemon-offline` (nas
  escritas) no lugar de um erro cru de dial.

Adições da Fase 3 (ainda não implementadas): token CSRF em rotas que mudam
estado, audit log para toda operação de escrita, limite de sessões por
conta, log-tail via WebSocket com redação server-side.
