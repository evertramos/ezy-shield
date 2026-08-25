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
    HostName servidor.exemplo.com
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
  usuário, sem controle de acesso por time; sessões ao vivo são
  limitadas a 3 simultâneas por conta (veja a referência do
  dashboard). Isso é ok para o escopo single-admin atual.

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
   credentials-file: /root/.cloudflared/<tunnel-uuid>.json
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
Instale Tailscale no servidor e no laptop e logue na mesma tailnet. O
tráfego é peer-to-peer via mesh, cifrado com WireGuard — sem IP
público nem DNS — e você pode restringir o acesso com ACLs no painel
do Tailscale.

**Importante:** o dashboard escuta só em `127.0.0.1:9090`, e sua
guarda de loopback rejeita qualquer bind não-loopback, então você
**não** pode simplesmente abrir o endereço tailnet do servidor na
porta 9090. Uma instalação Tailscale padrão (modo kernel) não
encaminha o tráfego destinado à tailnet para um listener só de
loopback — uma requisição a `http://<nome-tailnet-do-servidor>:9090`
chega em `100.x.y.z:9090`, não encontra listener e é recusada. (Falha
fechando — sem brecha de segurança — mas não funciona como URL
direta.) Ligue a tailnet ao dashboard de loopback de uma destas duas
formas:

- **`tailscale serve`** — o proxy reverso embutido do Tailscale. No
  servidor:

  ```bash
  # Encaminha o endereço tailnet do node (HTTPS) para o dashboard local em :9090.
  sudo tailscale serve --bg 9090
  tailscale serve status   # verifica; rode `tailscale serve --help` para desfazer
  ```

  Depois abra `https://<servidor>.<tailnet>.ts.net/` de qualquer
  dispositivo na tailnet. O Tailscale termina a conexão e a encaminha
  para `127.0.0.1:9090`, então o dashboard ainda vê um cliente de
  loopback e sua guarda de bind é satisfeita. (O serve HTTPS exige
  certificados HTTPS habilitados na sua tailnet; as flags exatas variam
  conforme a versão do Tailscale.)

- **Túnel SSH sobre Tailscale** — idêntico à Opção 1, mas apontando o
  SSH para o nome tailnet, de modo que nenhuma porta fica exposta:

  ```bash
  ssh -L 9090:127.0.0.1:9090 <usuário>@<nome-tailnet-do-servidor>
  # depois abra http://localhost:9090
  ```

Referência: <https://tailscale.com/kb/1017/install/> ·
<https://tailscale.com/docs/features/tailscale-serve>

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
