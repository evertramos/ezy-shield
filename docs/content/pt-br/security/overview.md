---
title: Visão Geral de Segurança
description: Postura pública de segurança e garantias
order: 1
---

# Visão Geral de Segurança

Esta página descreve o modelo de segurança do EzyShield do ponto de vista do usuário. Para a análise de ameaças detalhada, veja o SECURITY-REVIEW interno (disponível no repositório ezy-shield).

## Arquitetura

```
logs (SSH, Nginx)
  ↓
[ Collector ] — tail de arquivo, leitura do journald
  ↓
[ Parser ] — evento estruturado (IP, método, status)
  ↓
[ Rule Engine ] — scoring offline (roda sempre, sem rede)
  ↓
[ IA (opcional) ] — Anthropic/OpenAI/Ollama (só para eventos ambíguos)
  ↓
[ Decision Engine ] — decide ban/allow/defer
  ↓
[ Enforcer (com separação de privilégios) ] — aplica bans (nftables, Cloudflare)
```

**Princípio central: o daemon principal nunca detém privilégios elevados.** Mutações de firewall só acontecem através de um binário separado, o `ezyshield-enforcer`, que detém `CAP_NET_ADMIN`.

## Garantia de anti-lockout

O EzyShield tem uma regra dura: **sua sessão SSH ativa e os CIDRs de admin nunca podem ser banidos**, mesmo que casem com um padrão de ataque.

Antes de qualquer ban ser gravado no firewall, duas checagens independentes rodam em sequência:

1. **Checagem de allowlist**: o IP alvo é comparado com a allowlist estática —
   sua `allowlist` configurada, os `admin_cidrs` do policy.yaml e o peer SSH
   capturado quando o daemon iniciou.
2. **Re-checagem de SSH ao vivo**: o IP alvo é comparado com os peers SSH
   ativos agora — pela tabela de conexões do kernel (`/proc/net/tcp` e
   `/proc/net/tcp6`, pontas remotas de conexões estabelecidas na(s) porta(s)
   do sshd — funciona sob systemd, sem depender de ambiente; portas lidas do
   `sshd_config`, fallback 22) e, em contextos interativos, pela variável de
   ambiente `SSH_CLIENT` atual.

Se qualquer uma das checagens casar, o ban é rejeitado.

Bans manuais (`ezyshield ban`) passam exatamente pelos mesmos guards —
incluindo o rate limit de bans — e tentativas recusadas ficam registradas
no audit log.

Isso é garantido em código, não por uma rule. Nenhum threshold mal configurado consegue te trancar fora.

A checagem roda duas vezes, em camadas independentes: o motor de decisão
filtra primeiro, e um gate único na frente de todos os backends de
enforcement re-checa cada ban e cada reconcile antes de chegar ao nftables
ou a qualquer plataforma de edge. Mesmo um backend sem lógica própria de
allowlist nunca recebe um endereço protegido — inclusive via um sync que o
reintroduziria.

**A re-checagem de SSH ao vivo protege uma *conexão*, não um endereço para
sempre.** Um bruteforcer que reconecta mais rápido do que a tabela de peers é
relida mantém uma conexão estabelecida visível em toda avaliação, então cada
tentativa dentro da janela do threshold é (corretamente) recusada. Para fechar
a brecha em que uma rajada dessas nunca seria banida, um IP cujo ban foi
recusado *apenas* por causa de uma conexão SSH ativa é reavaliado logo depois
que essa conexão fecha — a partir do histórico de eventos ainda dentro da
janela, pelos mesmos guards (allowlist, uma nova sondagem de peer SSH ao vivo,
rate limit de bans). Se a conexão ainda estiver estabelecida no momento da
reavaliação — uma sessão legítima do operador — a recusa simplesmente se
repete e nada é banido. Um ban só pode resultar de uma checagem completa que
não encontrou nenhuma conexão SSH estabelecida naquele instante; a sessão do
operador continua imbanível enquanto estiver aberta.

## Supremacia da allowlist

A allowlist é checada PRIMEIRO, antes de qualquer decisão do rule engine. Um IP na allowlist não pode ser banido por nenhuma rule, decisão de IA ou tentativa de ban manual.

```yaml
allowlist:
  - 10.0.0.0/8       # rede interna
  - 198.51.100.7     # um host específico
admin_cidrs:
  - 192.0.2.0/24     # faixas de admin, re-checadas antes de cada ban
```

## Limite de taxa

Uma rule quebrada ou um feed envenenado não consegue banir a internet inteira. A trava `max_bans_per_minute` (default 30) rejeita bans excedentes com um erro explícito — nunca em silêncio, nunca descartando o limite. Bans de escalação que re-bloqueiam um IP cujo ban anterior terminou dentro da `escalation_exempt_window` (default 24h) ficam isentos dessa trava, para que um reincidente que já foi banido não volte a entrar enquanto o rate limit está saturado; bans de primeira ofensa sempre contam para a trava.

## Resiliência da detecção

Detecção só serve se continuar rodando. Cada fonte de log (um tail de arquivo,
um leitor de `journalctl`, um stream de container Docker) é vigiada por seu
próprio supervisor. Se um collector sofre uma falha transitória — um arquivo de
log momentaneamente ausente na inicialização, um `logrotate` cuja reabertura
demora, o `journald` reiniciando e matando o `journalctl` — o supervisor
**reinicia esse collector automaticamente** com backoff exponencial limitado,
de modo que um contratempo operacional rotineiro não desative silenciosamente a
detecção naquela fonte até o próximo restart do daemon.

O supervisor distingue uma falha real de um desligamento limpo: em
`SIGTERM`/`SIGINT` (cancelamento de contexto) os collectors param e **não** são
reiniciados, então o shutdown nunca entra em hot-loop. Um collector que falha
repetidamente dispara uma **notificação crítica** nomeando a fonte, para que
uma entrada permanentemente quebrada apareça para você em vez de tentar de novo
em silêncio. As demais fontes de log continuam rodando o tempo todo — um
collector com falha nunca derruba o pipeline.

## Tratamento de segredos

Nenhum segredo aparece em:
- Arquivos de config (use a sintaxe `env:VAR_NAME`)
- Saída de log
- Mensagens de erro
- Prompts de IA
- Audit trail

Tokens de API são resolvidos uma única vez no startup e nunca impressos. Se um segredo for referenciado em um erro, o erro é reescrito para omiti-lo.

## Segurança da IA

Quando a IA está habilitada para eventos ambíguos (scores dentro da `ambiguous_band` configurável):

1. **Validação de schema**: a saída da IA é parseada em um tipo estruturado; respostas malformadas causam uma decisão de fallback.
2. **Clamp pela policy**: a IA só pode sugerir dentro dos thresholds e durações de ban que você configurou. Ela não pode escalar além deles.
3. **Vínculo ao alvo**: um veredito só pode nomear um IP que estava no lote analisado. Se o modelo alucinar (ou for comprometido) e nomear qualquer outro endereço, o veredito é descartado com um warning — a IA nunca escolhe o alvo do ban, apenas pontua IPs que os logs de fato observaram.
4. **Audit trail**: todo veredito de IA (fonte, score, motivo) é persistido junto com o strike, então você pode auditar e sobrescrever se necessário.
5. **Sem prompt injection**: linhas de log são passadas como dados, nunca interpoladas em instruções. O prompt é fixo e controlado.

## Separação de privilégios

- **Daemon principal** (`ezyshield`): roda como usuário sem privilégios, lê logs, toma decisões, comunica-se via unix socket
- **Enforcer** (`ezyshield-enforcer`): detém apenas `CAP_NET_ADMIN`, aceita um conjunto fixo e tipado de verbos (`ping`, `add`, `del`, `list`, `flush` e os verbos de allowlist), muta o nftables de forma segura e idempotente

O enforcer não é uma biblioteca. É um processo separado. O daemon principal não pode modificar o firewall diretamente.

### A única concessão que muda isso: o grupo `docker`

Coletores de log docker (e o [observador de docker exec](../guides/docker-exec-watch.md))
leem através do socket do Docker Engine, e o acesso a esse socket é concedido
pela participação no grupo `docker`. Esse grupo **não** é uma permissão de
leitura — ele é a API do Engine. Qualquer processo que o alcance pode iniciar
um container com o filesystem do host montado, o que é root no host.

Portanto, em um host Docker onde o usuário de serviço está em `docker`, o
primeiro item acima deixa de valer: o daemon é equivalente a root, e o
hardening do systemd na unidade dele (`NoNewPrivileges`,
`ProtectSystem=strict`, seccomp) não o contém, porque a fuga é pedir ao daemon
do Docker — um processo root sem confinamento — que faça o trabalho.

Por isso o EzyShield nunca concede esse grupo por conta própria:

- o `ezyshield init` pergunta **apenas** quando você configura ao menos um
  coletor docker, o prompt tem **não** como padrão e ele nomeia a consequência;
- instalações scriptadas optam explicitamente com `--docker-group` (ou
  `collectors.docker_group: true` no arquivo de respostas). O `--yes` aceita
  padrões seguros, e este padrão é não;
- recusar ainda escreve os coletores — eles apenas não conseguem ler os logs
  dos containers enquanto o acesso não existir;
- o `ezyshield doctor` avisa sempre que o usuário de serviço está em `docker`,
  e diz se algo na sua configuração justifica isso.

Para verificar e revogar:

```bash
getent group docker                          # o ezyshield aparece na lista?
sudo gpasswd -d ezyshield docker             # revoga
sudo systemctl restart ezyshield             # tira o grupo do daemon em execução
```

Revogar desabilita os coletores docker. Se você quer logs de container sem um
daemon equivalente a root, as alternativas usuais são gravar os logs dos
containers em um caminho do host (um access log bind-mountado, lido por um
coletor `kind: file`) ou colocar um proxy somente-leitura, com filtro de
endpoints, na frente do socket do Engine. O caminho por arquivo não precisa de
nada do Docker e é o primeiro a considerar.

## Sem listeners de rede

O EzyShield não abre nenhum listener de rede para controle (o dashboard opcional faz bind apenas em um endereço loopback — `127.0.0.1` ou `::1` — e recusa qualquer outra coisa). O controle é via:
- CLI: `ezyshield ban`, `ezyshield list`, etc. (somente local)
- Unix socket: `/run/ezyshield/ezyshield.sock` (permissões de filesystem)

## Camadas de acesso do socket de controle

O acesso ao socket é imposto pelo kernel via grupo unix; o daemon adiciona
uma allowlist de verbos por cima (issue #212). Quem pode fazer o quê:

| Camada | Socket | Grupo | Verbos |
|---|---|---|---|
| Operador | `ezyshield.sock` | `ezyshield` | tudo: verbos de leitura mais `ban`, `unban`, `allow`, `unallow`, `arm`, `disarm`, `disable_all`, `prune`, `feeds_refresh` |
| Visualizador | `ezyshield-ro.sock` | `ezyshield-view` | somente leitura: `status`, `list`, `list_allow`, `events`, `report`, `subscribe` (watch), `metrics`, `feeds_status` |

Os dois sockets têm modo `0660` e — como todo unix socket — NÃO são
listeners de rede. A allowlist do visualizador é **fechada e
deny-by-default**: um verbo adicionado no futuro é recusado no socket
read-only até ser classificado deliberadamente como leitura. Pertencer ao
`ezyshield-view` nunca muta estado — sem unban, sem disarm, sem edição de
allowlist.

O postinstall dos pacotes cria os dois grupos; adicione um usuário de
monitoramento com `usermod -aG ezyshield-view <user>`. A CLI recua
automaticamente para o socket read-only quando o socket de operador nega
permissão, então usuários da camada de visualização rodam `ezyshield
status`, `list`, `watch` e `report` sem flags extras.

Toda requisição de verbo mutante — inclusive as recusadas — é registrada no
audit journal append-only como uma entrada `socket_cmd` com uid/gid do peer
requisitante (`SO_PEERCRED`), então "quem desarmou o daemon?" sempre tem
resposta.

## Fluxo de dados

Toda conexão de saída que o EzyShield pode fazer — providers de AI,
Cloudflare, atualizações de GeoIP, notifiers, `ezyshield update` — é opt-in e
está documentada, com gatilho, payload e forma de desligar, na
[Referência de Fluxo de Dados](../reference/data-flow.md). Aquela página
também traz a configuração exata para rodar totalmente local, com zero
tráfego de saída. Não há telemetria.

## Audit trail

Toda ação é registrada em SQLite:
- Quando: timestamp
- O quê: IP, rule, score, decisão (ban/allow/defer)
- Por quê: nome da rule, resposta da IA (se a IA foi consultada)

Exportação para compliance:

```bash
ezyshield report --json > report.json   # histórico por IP com evidências
```

## Sincronização com o Cloudflare

Ao usar Cloudflare Lists:

1. **Sync idempotente**: o EzyShield reconcilia sua visão com o Cloudflare no startup do daemon, a cada 5 minutos e sempre que bans expiram (adiciona entradas faltantes, remove as obsoletas)
2. **Fonte da verdade**: a tabela `bans_active` no SQLite é a fonte da verdade. Se o EzyShield cair e reiniciar, ele restaura os bloqueios do Cloudflare a partir do DB.
3. **Rules alheias preservadas**: o EzyShield só toca na sua própria lista de IPs (`ezyshield_blocked`) e nas rules de WAF que ele mesmo criou (marcadas pela descrição). Rules do Cloudflare criadas à mão ficam intactas.

## Dry-run por padrão

`armed: false` é o default no `policy.yaml`. Enforcement é opt-in. Você precisa definir explicitamente `armed: true` para começar a bloquear.

Antes de armar, rode em dry-run por 24+ horas e revise as decisões.

## Dependências

O EzyShield é distribuído como dois binários Go estáticos (`ezyshield` + o `ezyshield-enforcer` com separação de privilégios) com dependências mínimas de runtime:

- nftables do kernel Linux (para enforcement local)
- API do Cloudflare (opcional, TLS verificado)
- API do provedor de IA (opcional, TLS verificado)

Sem Python, sem Ruby, sem runtime Java. Sem inspeção de pacotes de terceiros. Sem módulos de kernel.

## Modelo de ameaças

**No escopo (protegemos contra):**
- Tentativas de login SSH por força bruta
- Scanners de login de WordPress/Drupal
- Port scanners e enumeração de serviços
- Bots e scrapers HTTP

**Fora do escopo:**
- Exploits de kernel
- Chaves SSH comprometidas
- Bugs de lógica na camada de aplicação
- Ameaças internas (insider threats)
- Comprometimento do provedor de IA (assumimos que a API da Anthropic/OpenAI é confiável)

## Compliance

O EzyShield mantém:
- Audit trail completo (consultável via SQL)
- Nenhum PII nos logs (apenas endereços IP)
- Limite de taxa para prevenir negação de serviço
- Allowlist para tráfego liberado
- Modo dry-run para testar antes do enforcement

Os dados desse audit trail podem sustentar requisitos de registro de requisições de SOC 2, ISO 27001 e GDPR — a compliance em si depende dos controles organizacionais que você constrói ao redor dele, não do EzyShield sozinho.

## Reportando problemas de segurança

Encontrou uma vulnerabilidade? Abra um security advisory privado no GitHub (aba Security → Report a vulnerability) — veja o [SECURITY.md](https://github.com/evertramos/ezy-shield/blob/main/SECURITY.md). Não abra uma issue pública.
