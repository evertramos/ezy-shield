---
title: Acesso remoto
description: Como acessar o dashboard com segurança da sua máquina local
order: 4
---

# Acesso remoto ao dashboard

O dashboard do EzyShield escuta **apenas** em loopback (`127.0.0.1`
ou `::1`). Essa é uma regra dura: ele se recusa a subir em qualquer
outro endereço. Cabe ao operador trazer a conexão de fora — de um
laptop, celular ou bastion — por um canal que já fala TLS ou é
confiável por outro motivo.

Este guia cobre os três padrões de transporte que recomendamos, na
ordem "mais fácil primeiro".

## Opção 1: SSH port-forward (recomendado)

A opção mais simples. Nada extra roda no servidor. Do seu laptop:

```bash
ssh -L 9090:127.0.0.1:9090 operador@servidor.exemplo.com
```

Depois abra `http://localhost:9090` no navegador. O tráfego passa
pelo canal SSH; o dashboard no servidor vê uma conexão local.

### Túnel em background

Se você quer o túnel aberto sem prender o terminal:

```bash
ssh -fN -L 9090:127.0.0.1:9090 operador@servidor.exemplo.com
```

- `-f` manda o processo para background *depois* da autenticação.
- `-N` diz "não rode comando remoto" — o túnel já é o objetivo.

Para matar depois:

```bash
kill $(pgrep -f "ssh -fN -L 9090")
```

### Setup persistente via ~/.ssh/config

Coloque a definição do túnel no seu config do SSH para subir com uma
palavra só:

```
Host ezyshield-dashboard
    HostName seu-servidor.com
    User operador
    LocalForward 9090 127.0.0.1:9090
    # Opcional: manter conexão viva por NATs.
    ServerAliveInterval 30
    ServerAliveCountMax 3
    # Opcional: morre em silêncio se o server sumir.
    ExitOnForwardFailure yes
```

Depois:

```bash
ssh ezyshield-dashboard
# abra http://localhost:9090 no navegador
```

Junte `-fN` para mandar para background, junte
`-o RemoteCommand=none` se sua conta usa comando forçado.

### Observações

- Se a porta 9090 já estiver ocupada localmente, escolha qualquer
  porta livre e mude o primeiro número: `-L 9091:127.0.0.1:9090`
  mapeia `http://localhost:9091` para a 9090 do lado do servidor.
- O túnel te dá exatamente o que uma sessão local dá — sem multi-
  usuário, sem controle de acesso por time, um login por vez. Isso
  é ok para o escopo single-admin atual.

## Opção 2: Cloudflare Tunnel (persistente, sem portas abertas)

Boa quando você quer uma URL estável que dá para favoritar e
controlar o acesso via Cloudflare Access. O servidor nunca abre uma
porta escutando além da conexão de saída do `cloudflared` para o
Cloudflare.

Passos em alto nível:

1. Crie uma conta Cloudflare e uma zone que você controle.
2. Instale o `cloudflared` no servidor:
   <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/>
3. Autentique: `cloudflared tunnel login` — abre um fluxo de browser
   amarrado à sua conta Cloudflare.
4. Crie um tunnel: `cloudflared tunnel create ezyshield`.
5. Aponte para um hostname:
   `cloudflared tunnel route dns ezyshield dashboard.seu-dominio.exemplo`.
6. Configure o ingress em `~/.cloudflared/config.yml`:

   ```yaml
   tunnel: ezyshield
   credentials-file: /root/.cloudflared/`<tunnel-uuid>`.json
   ingress:
     - hostname: dashboard.seu-dominio.exemplo
       service: http://127.0.0.1:9090
     - service: http_status:404
   ```

7. Rode: `cloudflared tunnel run ezyshield`, ou instale como
   serviço.
8. **Proteja o acesso via Cloudflare Access.** No painel Zero Trust
   do Cloudflare, adicione uma Access application para
   `dashboard.seu-dominio.exemplo` e exija um identity provider
   (Google, GitHub, Okta, PIN por e-mail, etc.). Sem esse passo
   qualquer um com a URL consegue chegar na página de login.

Referência:
<https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>

O dashboard no servidor continua ligado apenas em `127.0.0.1` — só
o `cloudflared` fala com ele, e só o Cloudflare fala com o
`cloudflared`.

## Opção 3: Tailscale (mesh privada, config zero)

Boa quando você já tem uma mesh Tailscale ligando time e máquinas.
Instale Tailscale no servidor e no laptop, logue na mesma tailnet,
depois abra `http://<nome-tailnet-do-servidor>:9090` pelo laptop.

Como o Tailscale não precisa de IP público nem DNS público — o
tráfego é peer-to-peer via mesh, cifrado com WireGuard — o dashboard
continua tão privado quanto era. Você pode restringir mais o acesso
com ACLs no painel do Tailscale.

Referência: <https://tailscale.com/kb/1017/install/>

Repare que a guarda de loopback do próprio dashboard **não** aceita
a interface do tailnet. Você continua chegando no daemon pela
interface do tailscale do lado do cliente, o que o Tailscale faz de
forma transparente — você digita `http://kylian-s:9090` e o
Tailscale roteia para o loopback do host destino.

## Nunca exponha 0.0.0.0

Para constar: não faça isso. Mesmo que você coloque
`addr: 0.0.0.0:9090` no config, o dashboard se recusa a subir com
um erro explícito citando `AGENTS.md §2`. É proposital. Se você
está tentado a burlar, uma das três opções acima quase sempre
resolve a necessidade real — um caminho remoto persistente sem
listener exposto.

## E se o daemon estiver offline?

Nenhum desses transportes toca a conexão com o daemon: em todos os
casos o dashboard alcança o daemon por um socket unix local. Se o
daemon estiver parado, todas as opções acima ainda entregam o banner
"Daemon offline" no lugar dos dados ao vivo. Suba o daemon
(`systemctl status ezyshield`) — o túnel não precisa mudar.
