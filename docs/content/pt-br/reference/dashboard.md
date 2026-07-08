---
title: Dashboard
description: Dashboard web para monitoramento e controle
order: 1
---

# Dashboard

O dashboard do EzyShield é uma pequena UI web que roda ao lado do daemon e
oferece aos operadores uma visão via navegador do estado do daemon, banimentos
ativos, histórico de strikes, allowlist e logs.

**Status:** Fase 1 — apenas o esqueleto de autenticação. As visões em tempo
real, o ban/unban manual e o log-tail via WebSocket entram em fases seguintes
(issue #56).

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
ezyshield dashboard --addr 127.0.0.1:9091 --auth-db /tmp/auth.db
```

Se o `config.yaml` estiver ausente, o dashboard cai para
`127.0.0.1:9090` e `/var/lib/ezyshield/dashboard.db` — assim o operador
consegue experimentar a UI antes mesmo do daemon estar totalmente
inicializado.

---

## Rotas

| Método | Path      | Auth       | Notas                                             |
|--------|-----------|------------|---------------------------------------------------|
| GET    | `/login`  | dispensada | Formulário de login                               |
| POST   | `/login`  | dispensada | Submit do form; grava cookie de sessão no sucesso |
| POST   | `/logout` | dispensada | Limpa o cookie de sessão                          |
| GET    | `/`       | obrigatória | Placeholder do índice (Fase 2 substitui)         |

Requests não autenticados em `/` recebem `303 See Other` para `/login`.

Cookies de sessão:
- nome `ezyshield_dashboard`,
- token hex de 32 bytes do `crypto/rand` (256 bits de entropia),
- `HttpOnly`, `SameSite=Strict`,
- expiração deslizante de 30 minutos ociosos,
- guardados **apenas em memória** — reiniciar o daemon força novo login.

O cookie **não** vem com `Secure`, porque o dashboard é servido em HTTP puro
via loopback; se você precisa de TLS, ele deve terminar no túnel gerenciado
pelo operador (Cloudflare, SSH, reverse proxy).

---

## Postura de segurança

- **Bind guard:** só loopback, verificado duas vezes (construção e start).
- **Armazenamento de senha:** PBKDF2-SHA256, 600 000 iterações, sal
  aleatório por hash, comparação em tempo constante.
- **Guarda contra enumeração:** o handler de login devolve a mesma resposta
  401 e a mesma mensagem para “usuário inexistente” e “senha errada”.
- **Session store:** em memória, protegido por mutex, token opaco, expiração
  deslizante.
- **Templates:** renderizados com `html/template`; qualquer string vinda do
  operador passa pelo auto-escape.
- **Permissões do DB de auth:** diretório pai criado com `0700`, arquivo em
  `chmod 0600` após aplicar o schema.

Adições da Fase 2 (ainda não implementadas): token CSRF em rotas que mudam
estado, audit log para toda operação de escrita, limite de sessões por conta.
