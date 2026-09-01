---
title: Docker + nginx + WordPress
description: Proteja um host Docker com proxy nginx
order: 4
---

# Implantando o EzyShield — host Docker com nginx-proxy + múltiplos containers WordPress

Este guia conduz um administrador de servidor na proteção de um setup típico: um
host rodando Docker, um container de **proxy reverso nginx** na frente de vários
containers **WordPress**. Os ataques que importam aqui são brute force de SSH no
host, brute force de login do WordPress (`/wp-login.php`, `/xmlrpc.php`) e
scraping de bots/scanners — todos bloqueados no firewall do host (e,
opcionalmente, na Cloudflare).

---

## 0. A ideia central (leia isto primeiro)

O EzyShield roda **no host, não dentro de um container.** Ele precisa (a) ler os
access logs do proxy e os logs de SSH do host, e (b) escrever regras de firewall
no kernel do host. Um container não consegue fazer nenhuma das duas coisas com
segurança. Então instalamos o binário no host e apenas o apontamos para os
arquivos de log que seus containers já escrevem.

A única coisa que você precisa acertar: **o IP real do visitante tem que chegar
aos logs.** Atrás do Docker, seu proxy nginx enxerga o IP da bridge do Docker, a
menos que esteja configurado para registrar o `X-Forwarded-For`. A seção 3 cuida
disso — se você pular essa parte, o EzyShield vai tentar banir a rede interna do
Docker. (O anti-lockout só protege seu peer SSH atual e os `admin_cidrs`
configurados — isso não vai evitar esse caso. Corrija a fonte do log direito.)

---

## 1. Pré-requisitos

- Host Linux (Ubuntu 22.04+/Debian 12+/RHEL 9+), acesso root/sudo
- `nftables` disponível no host (`nft --version`)
- Seu proxy escrevendo access logs num caminho do host (um bind-mount, veja §3)
- Opcional: um token de bot do Telegram e/ou um token de API da Cloudflare

---

## 2. Instalação (no host)

```bash
curl -sfL https://get.ezyshield.com | sudo sh
ezyshield version
```

Ou instale o `.deb`/`.rpm` assinado — veja o [guia de instalação](../getting-started/install.md).

---

## 3. Garanta que o proxy registre o IP *real* do cliente

Duas partes: o proxy precisa **registrar** o IP real, e o EzyShield precisa
conseguir **ler** o arquivo de log no host.

### 3a. Exponha o arquivo de log para o host

Você tem **três opções** — escolha uma:

**Opção A — bind-mount do diretório de logs do proxy (explícita, a mais simples de raciocinar):**

```yaml
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy   # ou seu próprio nginx
    volumes:
      - /var/log/nginx-proxy:/var/log/nginx   # <-- caminho no host : caminho no container
    # ...
```

Agora o host enxerga os access logs em `/var/log/nginx-proxy/access.log`.

**Opção B — ler direto o stdout capturado pelo próprio Docker (sem bind-mount):**
Se seus containers logam para stdout (o padrão das imagens oficiais de
nginx/WordPress) e você usa o driver `json-file` com rotação — como faz o popular
setup [evertramos/nginx-proxy-automation](https://github.com/evertramos/nginx-proxy-automation)
— o Docker já armazena esses logs no host em:

```
/var/lib/docker/containers/<container-id>/<container-id>-json.log
```

O EzyShield consegue ler esses arquivos diretamente — descubra o id do container
com `docker ps --no-trunc`. Configure uma rotação sensata no seu compose para os
arquivos não crescerem para sempre:

```yaml
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
```

> A Opção B é conveniente e mantém seu compose limpo; a Opção A dá um caminho
> estável e legível, independente dos IDs de container (que mudam a cada
> recriação). Se você recria containers com frequência, prefira a A — o caminho
> da B muda junto com o ID do container.

**Opção C — um collector `kind: docker`** lê os logs de um container através da
API do Docker Engine, em vez de um arquivo. É a opção mais conveniente, e a
forma como você concede esse acesso decide quanto do host o EzyShield alcança:
veja a §4a antes de escolhê-la. As opções A e B não precisam de nada do Docker.

### 3b. Registre o IP real do cliente
Se os clientes chegam **diretamente** ao nginx, os logs padrão já contêm o IP
real — pronto.

Se há algo na frente (Cloudflare, um load balancer, outro proxy), o nginx enxerga
*isso* como cliente. Configure o `real_ip` para que o `$remote_addr` logado seja
o visitante verdadeiro (e para que o EzyShield não bana seu CDN):

```nginx
# na config do nginx do proxy
set_real_ip_from 173.245.48.0/20;   # seus upstreams confiáveis / faixas da Cloudflare
real_ip_header   X-Forwarded-For;
real_ip_recursive on;
```

> **Nota crítica de segurança:** só confie no `X-Forwarded-For` vindo de
> upstreams que você de fato controla (as faixas de `set_real_ip_from` acima).
> Se o proxy confiar nele vindo de qualquer um, atacantes forjam o header e
> conseguem fazer IPs *inocentes* serem banidos. O EzyShield lê o IP real que o
> proxy resolver na linha de log — acerte o lado do nginx e o EzyShield bane o
> endereço certo.

### 3c. Logs do WordPress por container (opcional)
Se preferir ler o access log de cada container WordPress individualmente, faça
bind-mount de cada um para fora e adicione todos na §4. Normalmente o log único
do proxy é suficiente e mais simples — comece por ele.

---

## 4. Configure o EzyShield

```bash
sudo ezyshield init      # wizard interativo; escreve /etc/ezyshield/*.yaml
```

> **Pre-flight:** antes de imprimir o banner
> "Detecting environment...", o `ezyshield init` faz stat de
> `<config-dir>/config.yaml` e `<config-dir>/policy.yaml`. Se qualquer um já
> existir, o wizard falha rápido (em ~1s) com um único erro listando todos os
> caminhos pré-existentes — para você não responder o questionário inteiro só
> para descobrir no final que ele não conseguiu escrever. Para regenerar,
> apague os arquivos listados e rode de novo. A mesma checagem honra
> `--config-dir <path>` para diretórios de destino fora do padrão.

Ou escreva `/etc/ezyshield/config.yaml` diretamente. Os collectors leem seus
logs; enforcement e notificações são configurados aqui, enquanto thresholds e a
allowlist ficam no `policy.yaml`:

```yaml
# /etc/ezyshield/config.yaml — o que observar e como agir
collectors:
  - kind: journald            # brute force de SSH no host
    unit: ssh
  - kind: file                # o access log do proxy
    path: /var/log/nginx-proxy/access.log
    parser: nginx

enforce:
  nftables: {}                # firewall local (table/set padrão)

notify:
  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_TOKEN   # segredos vêm do env, nunca inline
    chat_ids: ["987654321"]
```

```yaml
# /etc/ezyshield/policy.yaml — decisões, escalação e segurança
armed: false                  # dry-run até você ter confiança (default)
ban_threshold: 70

strikes:
  - ttl: 5m
  - ttl: 1h
  - ttl: 24h
  - ttl: 168h
  - ttl: 0                    # permanente

# Nunca bloqueie estes — seu próprio acesso. O peer SSH atual + admin_cidrs
# entram automaticamente na allowlist antes de cada ban.
allowlist:
  - 203.0.113.7               # seu IP de casa/escritório  (ALTERE ISTO)
admin_cidrs:
  - 192.0.2.0/24
```

As assinaturas de WordPress (floods em wp-login.php / xmlrpc.php, caminhos de
sondagem de exploits) já vêm embutidas nas rules distribuídas — nenhuma
configuração é necessária. Para customizar thresholds, descomente a regra
relevante em `/etc/ezyshield/rules.d/10-wordpress.yaml` (gravado pelo `init`)
e ajuste — veja [Customizando Regras de Detecção](rules-customization.md).

### 4a. Se você escolheu collectors docker: como o EzyShield alcança o Engine

Um collector `kind: docker` lê através da API do Docker Engine. Há três formas
de dar esse acesso, e elas não são equivalentes — o `init` oferece as três
quando detecta collectors docker, nesta ordem:

**1. Um arquivo de log no host (nenhum acesso ao Docker).** As opções A e B da
§3a já fazem isso: o container grava o access log em um caminho bind-mountado
do host e um collector `kind: file` o lê. Nada do Docker é concedido. Considere
isso primeiro. O `init` pré-seleciona essa opção quando a mesma execução já lê
o log daquele servidor web a partir de um arquivo do host; ele imprime o volume
de compose necessário, mas nunca edita a sua stack.

**2. Um proxy somente-leitura do socket (o caminho restrito).** Um container
pequeno com filtro fica na frente do socket do Engine, serve logs e eventos de
container e recusa criação de container, exec e mounts. O EzyShield fala com
ele por TCP em loopback e fica fora do grupo `docker`. Adicione-o à sua stack:

```yaml
services:
  ezyshield-docker-proxy:
    image: tecnativa/docker-socket-proxy
    restart: unless-stopped
    environment:
      CONTAINERS: 1        # GET /containers/<nome>/logs
      EVENTS: 1            # GET /events (observador de docker exec)
      POST: 0              # recusa create/exec/start de container
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "127.0.0.1:2375:2375"
```

e aponte o EzyShield para ele:

```yaml
docker:
  host: tcp://127.0.0.1:2375
```

A porta é publicada em `127.0.0.1` para que a API do Engine nunca fique
alcançável de outro host. O EzyShield não abre nenhum listener para isso — o
proxy é um container da sua stack, e é a única coisa que toca o socket. É
maquinário extra, honestamente: mais um container para rodar e atualizar,
embora ele não toque em nenhum container da sua aplicação.

Instalações scriptadas escolhem esse caminho com
`--docker-host tcp://127.0.0.1:2375` (chave de resposta:
`collectors.docker_host`). O `init` escreve o `docker.host` e imprime o trecho
acima; ele nunca inicia o proxy para você. Depois que ele estiver rodando,
verifique:

```bash
ezyshield doctor
```

O doctor sonda o endpoint: ele precisa responder `GET /_ping` e precisa
**recusar** `POST /containers/create`. Um endpoint que aceita criação de
container é acesso equivalente a root a este host pela rede, e o doctor FALHA
nele.

**3. O grupo `docker` (último recurso).** A participação nesse grupo é a API do
Engine, não uma permissão de leitura — um processo que o alcança pode iniciar
um container com o filesystem do host montado, o que é root no host. Colocar o
usuário de serviço ezyshield nele torna o daemon que faz parsing de log — o
componente que consome entrada controlada por atacantes o dia inteiro —
equivalente a root. Por isso o `init` pergunta antes de conceder, com **não**
como padrão:

```
Grant the ezyshield service user access to the Docker socket? This adds it to
the 'docker' group, which is root-equivalent on this host (any process running
as ezyshield could start a privileged container). Required for docker log
collectors. [y/N]
```

- Responda **não** e os collectors ainda são escritos — eles apenas não leem
  nada enquanto o acesso não existir.
- Responda **sim** e a concessão é um trade-off deliberado e documentado.
- Instalações scriptadas optam com `--docker-group`, ou
  `collectors.docker_group: true` no arquivo de respostas. O `--yes` sozinho
  nunca concede. `--docker-group` e `--docker-host` são mutuamente exclusivas.

Uma instalação provisionada antes pode já estar no grupo: nem uma atualização
de pacote nem uma nova execução do `init` a revogam. Verifique e revogue com:

```bash
ezyshield doctor            # avisa quando o usuário de serviço está no grupo docker
getent group docker         # o ezyshield aparece na lista?
sudo gpasswd -d ezyshield docker
sudo systemctl restart ezyshield
```

Veja a [visão geral de segurança](../security/overview.md) para o quadro completo.

Segredos vão num arquivo env que a unit do systemd carrega (o `ezyshield init` o
cria com modo 0600; o `doctor` checa suas permissões):

```bash
sudo tee /etc/ezyshield/.env >/dev/null <<'EOF'
EZYSHIELD_TELEGRAM_TOKEN=123456:abc...
EOF
sudo chmod 600 /etc/ezyshield/.env
```

---

## 5. Verifique antes de armar

```bash
sudo ezyshield doctor          # checa config, permissões, nft, leitura dos logs
sudo ezyshield config validate # checagem estrita de schema
sudo ezyshield test notifier telegram
```

Depois rode o daemon em primeiro plano e observe o que ele *faria* (ele
permanece em dry-run até você definir `armed: true`):

```bash
sudo ezyshield run             # registra decisões "dry_ban (would ban ...)"
```

Deixe rodando com tráfego real por um dia. Confirme:
- ele sinaliza atacantes de verdade (tente alguns logins SSH errados a partir do
  hotspot do seu celular)
- ele **não** sinaliza o seu próprio IP, seu CDN nem a rede do Docker
- os IPs exibidos são IPs reais de visitantes, não endereços `172.x` do Docker
  (se forem, corrija a §3b)

---

## 6. Arme

Mude para `armed: true` no `policy.yaml` (NÃO no config.yaml — o loader estrito rejeita chaves desconhecidas lá) e então rode para valer como serviço:

As units do systemd são instaladas pelo `ezyshield init` (ou pelo pacote
deb/rpm). Habilite e inicie:

```bash
sudo systemctl enable --now ezyshield-enforcer ezyshield
systemctl status ezyshield
```

Agora os bans estão ativos. Acompanhe:

```bash
ezyshield status                 # saúde do daemon/enforcer, modo, bans ativos
ezyshield list                   # IPs banidos no momento + nº do strike + expiração
ezyshield watch                  # stream de eventos ao vivo no seu terminal
```

Controle manual a qualquer momento:

```bash
sudo ezyshield ban 203.0.113.7 --ttl 24h --reason "manual"
sudo ezyshield unban 203.0.113.7
sudo ezyshield allow 198.51.100.9     # adiciona à allowlist
```

---

## 7. Opcional: bloqueie também na Cloudflare

Se seus sites WordPress ficam atrás da Cloudflare, bloquear na edge barra os
atacantes antes mesmo de chegarem ao seu host:

```yaml
enforce:
  nftables: {}
  cloudflare:
    api_token: env:CLOUDFLARE_API_TOKEN     # restrinja o escopo a "Account Filter Lists: Edit"
    account_id: "your-account-id"   # obrigatório no modo padrão "lists"
```

O EzyShield então escreve os bans *tanto* no firewall do host quanto na
Cloudflare, e os mantém em sincronia. Veja o [guia da Cloudflare](cloudflare.md)
para o escopo do token e os modos lists vs. rulesets.

---

## 8. Opcional: ligue a análise por IA

O rule engine funciona sem IA nenhuma. Para deixar a IA julgar os casos ambíguos
(esse crawler agressivo é um usuário real ou um scraper?):

```yaml
ai:
  provider: anthropic            # anthropic | openai | ollama
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  token_budget_daily: 50000      # teto diário rígido; o rule engine assume se for excedido
```

Só agregados suspeitos são enviados, já minimizados em resumos como
`IP 203.0.113.7 → 412 POSTs to /wp-login.php in 60s`, e os vereditos são cacheados —
então o uso de tokens fica minúsculo.

---

## 9. Se algo der errado — botão de pânico

Pare novos bans imediatamente e derrube todos os bloqueios locais de uma vez:

```bash
sudo systemctl stop ezyshield          # o daemon para de decidir
sudo nft delete table inet ezyshield   # todos os bloqueios locais somem num comando
```

O EzyShield mantém toda regra que escreve dentro da sua própria table
`inet ezyshield` e nunca toca em regras fora dela — apagar essa table limpa
todos os bloqueios locais do EzyShield e nada mais. Ele também nunca bloqueia a
sua sessão SSH ativa (o anti-lockout re-checa antes de cada ban).

Para desbloquear um IP específico em todo lugar (host **e** a edge da Cloudflare
configurada):

```bash
sudo ezyshield unban 203.0.113.7
```

As entradas na edge da Cloudflare são removidas por IP pelo `unban`. Para limpar
uma lista inteira da edge de uma vez, use o painel da Cloudflare
(Manage Account → Configurations → Lists) — um bloqueio na edge continua
rejeitando tráfego mesmo depois que você para o daemon local, então não se
esqueça dele.

Para remover o EzyShield do host por completo, use `scripts/wipe.sh` (para e
remove serviços, units, binários, regras de nftables, o usuário de serviço e —
opcionalmente — os dados).

---

## Solução de problemas

| Sintoma | Causa provável | Correção |
|---|---|---|
| Está banindo `172.x.x.x` / IPs do Docker | o proxy loga o IP do container, não do cliente | configure o `real_ip` do nginx (§3b) |
| Nada é detectado | caminho de log errado ou o parser não reconhece o formato | `ezyshield doctor`; confira `path`/`parser` do collector em `config.yaml` |
| Um collector `kind: docker` não lê nada | o usuário de serviço não alcança o Docker Engine | `ezyshield doctor`; aponte o `docker.host` para um proxy somente-leitura, troque por um collector de arquivo, ou conceda o grupo deliberadamente (§4a) |
| O `doctor` diz que o endpoint docker aceita criação de container | o `docker.host` aponta para o próprio engine, ou para um proxy com escrita habilitada | coloque um proxy com filtro na frente e dê a ele `POST: 0` (§4a, opção 2) |
| Fiquei brevemente trancado para fora | allowlist sem o seu IP | o anti-lockout deveria impedir; adicione seu IP à `allowlist` |
| Telegram em silêncio | token/chat_id ou env não carregado | `ezyshield test notifier telegram`; confira as permissões do `.env` |
| Visitantes reais bloqueados | o proxy confia no XFF de fonte não confiável | restrinja `set_real_ip_from` a upstreams que você controla |

---

## TL;DR

1. Instale o binário **no host** (não num container).
2. Faça bind-mount do access log do seu proxy para o host; garanta que ele loga o IP **real** do cliente.
3. `ezyshield init`, coloque seu IP na allowlist, mantenha `armed: false`.
4. `sudo ezyshield run` por um dia (modo dry-run; `armed: false`), confirme que está fazendo sentido.
5. Mude para `armed: true`, `systemctl enable --now ezyshield`.
6. (Opcional) adicione bloqueio na edge da Cloudflare e/ou análise por IA.
