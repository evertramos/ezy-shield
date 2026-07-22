---
title: Referência de Policy
description: Referência completa de policy.yaml
order: 3
---

# Referência de Policy

Referência completa de `/etc/ezyshield/policy.yaml` — thresholds de decisão, escalação de strikes, limites de segurança e modo de enforcement. Todos os campos abaixo existem na versão atual; o arquivo é validado de forma estrita (chaves desconhecidas são rejeitadas).

## Exemplo completo (todos os campos, com defaults)

```yaml
# Dry-run por padrão: nada é bloqueado até você definir armed: true.
armed: false

# Thresholds de score (rule engine + IA produzem um score 0-100)
ban_threshold:     70   # score >= isto gera um strike
observe_threshold: 40   # score em [observe, ban) -> só log/notificação

# Escalação de strikes: TTL do ban por contagem acumulada de strikes.
# TTL 0 significa ban permanente.
strikes:
  - ttl: 5m     # strike 1
  - ttl: 1h     # strike 2
  - ttl: 24h    # strike 3
  - ttl: 168h   # strike 4 (7 dias)
  - ttl: 0      # strike 5 — permanente

# Trava global de segurança: máximo de bans por minuto.
max_bans_per_minute: 30

# Escalações (strike > 1) pulam a trava apenas quando o ban anterior
# terminou dentro desta janela. Default 24h; acima de 168h é reduzido.
escalation_exempt_window: 24h

# Diagnóstico ban_ineffective: dispara quando um IP banido continua
# gerando eventos de log (anomalia de enforcement — ex.: CDN na frente).
# Os dois valores são pisos: a policy pode aumentá-los, nunca reduzi-los.
ban_ineffective_grace: 90s
ban_ineffective_min_events: 3

# IPs/CIDRs que NUNCA podem ser banidos. Allowlist vence tudo.
allowlist: []

# CIDRs de admin mesclados na allowlist em runtime, no startup e antes de cada ban.
admin_cidrs: []

# Bloqueio geográfico (opcional; requer enriquecimento GeoIP — ignorado
# silenciosamente sem ele). Tráfego correspondente ganha um grande boost
# de score, não um ban instantâneo.
block_countries: []   # ISO 3166-1 alpha-2, ex.: [CN, RU]
block_asns: []        # ex.: [AS16276, AS14061]
```

## armed

| Campo | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `armed` | bool | `false` | `true` = aplica bans; `false` = dry-run: o pipeline inteiro roda e registra decisões `dry_ban`, mas nada é bloqueado e nada é gravado no store de bans |

Dry-run é o padrão de propósito — rode assim até o `ezyshield doctor` estar limpo e as decisões no log fazerem sentido.

## Thresholds

| Campo | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `ban_threshold` | int (1–100) | 70 | Score igual ou acima disto gera strike/ban |
| `observe_threshold` | int (0–ban_threshold) | 0 | Score em `[observe_threshold, ban_threshold)` gera notificação sem strike; abaixo disso, o evento é apenas registrado |

Scores vêm do rule engine (veja `configs/rules.yaml`) e, em casos ambíguos, do provedor de IA opcional — cujo veredito é consultivo e sempre limitado por esta policy.

## strikes

Tabela de escalação indexada pela contagem acumulada de strikes do IP; contagens além do fim da tabela usam a última entrada.

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `strikes[].ttl` | duração ou `0` | Duração do ban naquele strike. `0` = permanente |

Escada padrão: `5m → 1h → 24h → 168h → permanente`.

Semântica (um episódio = um strike): enquanto um ban está ativo, novos eventos daquele IP nunca somam strikes — são suprimidos e contados. A escada só avança quando o IP reincide **depois** que o ban expira. Escalação descontrolada a partir de uma única rajada é estruturalmente impossível.

## Limites de taxa

| Campo | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `max_bans_per_minute` | int (>0) | 30 | Trava global de bans por minuto. Exceder retorna erro em vez de descartar o limite em silêncio — um feed envenenado ou bug de parser não consegue banir a internet |
| `escalation_exempt_window` | duração | `24h` (máx `168h`) | Uma escalação (strike > 1) pula a trava apenas quando o ban anterior **terminou dentro desta janela** — re-bloquear um IP que estava bloqueado há instantes não adiciona risco de lockout. Mais antigo que isso conta na trava como um ban novo. Valores acima de 7d são reduzidos |

## Diagnóstico ban_ineffective

Num setup armado saudável, um IP banido não consegue gerar novas linhas de log — os pacotes morrem no firewall. Eventos de log mencionando um IP banido sinalizam, portanto, uma anomalia de enforcement (CDN na frente do servidor, conntrack não descarregado, divergência v4/v6). O EzyShield emite um WARN estruturado `ban_ineffective`, uma vez por ban, com contexto da escada.

| Campo | Tipo | Piso/Default | Descrição |
|-------|------|--------------|-----------|
| `ban_ineffective_grace` | duração | 90s | Eventos dentro desta janela após o ban são contados mas nunca disparam o diagnóstico (requisições em voo, buffer de proxy, latência de log) |
| `ban_ineffective_min_events` | int | 3 | Eventos suprimidos após a janela de graça necessários para disparar o WARN |

Ambos são pisos: a policy pode aumentá-los, nunca reduzi-los. O diagnóstico nunca escala um ban — o remédio que ele aponta é enforcement na borda ou parsing de real-IP, não sentença mais dura.

## allowlist e admin_cidrs

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `allowlist` | lista de IP/CIDR | Nunca banidos, checada **primeiro**, incontornável — vence rules, IA e bloqueio geográfico |
| `admin_cidrs` | lista de CIDR | Mesclados na allowlist em runtime no startup e re-checados antes de cada ban (anti-lockout) |

O peer SSH ativo é adicionalmente re-derivado antes de cada ban e nunca pode ser banido.

```yaml
allowlist:
  - 192.0.2.0/24          # seu escritório
  - 198.51.100.7          # um host específico
admin_cidrs:
  - 10.0.0.0/8
```

Como uma faixa na allowlist **nunca** pode ser banida, mantenha as entradas
tão estreitas quanto o tráfego que você realmente precisa isentar — uma faixa
privada ampla remove o enforcement de tudo o que está dentro dela, de forma
permanente.

### Hosts com Docker

Quando o `ezyshield init` detecta Docker, ele coloca na allowlist apenas as
sub-redes de rede bridge que realmente existem no host (enumeradas via
API/CLI do Docker), nunca uma faixa RFC1918 genérica. Se a enumeração falhar,
ele recua para a sub-rede padrão do bridge do próprio Docker
(`172.17.0.0/16`) sozinha — ainda assim nunca o `172.16.0.0/12` inteiro.
Hosts sem Docker não recebem nenhuma entrada relacionada a Docker na
allowlist.

O `policy.yaml` gerado inclui um exemplo comentado para adicionar
deliberadamente uma faixa interna mais ampla (VPN, LAN do escritório, um
overlay Docker multi-host):

```yaml
# To allow a broader internal range (VPN, office LAN, a multi-host docker
# overlay) deliberately, uncomment and edit the line below.
# Trade-off: an allowlisted range can NEVER be banned (allowlist always wins
# over rules, AI, and geo blocking) — the broader the range, the more of your
# network permanently loses enforcement coverage.
# 'ezyshield doctor' warns if any private allowlist entry is /16 or broader.
#   - 10.0.0.0/8
```

O `ezyshield doctor` avisa (não falha) quando a allowlist contém uma faixa
privada (RFC1918/ULA) `/16` ou mais ampla, seja qual for a origem dela.

> **Atualizando de uma versão anterior do EzyShield?** O `init` nunca
> reescreve um `policy.yaml` existente, então uma config gerada antes desta
> correção mantém a entrada `172.16.0.0/12` sem alteração. Revise a seção
> `allowlist` do seu `policy.yaml` e estreite essa entrada para a(s) sua(s)
> sub-rede(s) real(is) de bridge do Docker (`docker network ls` /
> `docker network inspect`) — o `ezyshield doctor` sinaliza a entrada antiga
> como WARN para te lembrar.

## Bloqueio geográfico

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `block_countries` | lista de códigos ISO alpha-2 | Tráfego destes países ganha boost de +100 no score |
| `block_asns` | lista de `AS<número>` | Mesma semântica por sistema autônomo |

Requer enriquecimento GeoIP ativo; ignorado silenciosamente sem ele. O boost empurra o tráfego acima do `ban_threshold` — a allowlist continua vencendo, e um match de país/ASN sozinho nunca contorna a escada de strikes.

## Validação

```bash
sudo ezyshield config validate   # checagem estrita de schema + restrições
sudo ezyshield doctor            # checagem completa do ambiente
```

Chaves desconhecidas falham a validação; valores fora de faixa (ex.: `ban_threshold: 0`, `max_bans_per_minute: 0`) são rejeitados com o motivo exato.

## Tier SSH probe / agressivo

O parser de SSH reconhece muito mais variantes de linha do que aquelas que geram ban. Todo evento SSH carrega um de quatro kinds:

| Kind | O que é | Contado pelas rules padrão? |
|------|---------|------------------------------|
| `ssh_invalid_user` | tentativa de auth contra usuário inválido/desconhecido/não permitido | **sim** |
| `ssh_fail` | tentativa de auth contra usuário válido/conhecido | **sim** |
| `ssh_probe` | anomalia de conexão/protocolo ou eco de terminação/PAM corroborante (scanners, `Connection closed by <ip>` puro, erros de `banner exchange`, resets de `kex`, `pam_unix ... authentication failure`) | **não** |
| `ssh_accept` | login bem-sucedido | nunca (só telemetria) |

Reconhecer uma linha nunca bane ninguém — só uma rule que *conta* aquele kind bane.
As rules `ssh_bruteforce` embutidas contam apenas os dois kinds de tentativa real, então a postura padrão tem taxa de falso positivo próxima de zero.

Para banir também scanners e handshakes malformados, habilite a rule agressiva opt-in que vem comentada em `configs/rules.yaml`:

```yaml
rules:
  - name: ssh_probe_aggressive
    description: "SSH scanners / malformed connections"
    kinds: [ssh_probe]
    window: 60s
    threshold: 10
    score: 60
    category: scanner
```

> **Risco maior de falso positivo.** `ssh_probe` dispara em churn puro de conexão,
> que um cliente legítimo atrás de CGNAT ou uma rede instável também produz.
> Deixe desligada a menos que você entenda seu tráfego, e sempre em par com uma
> `allowlist` correta. A linha específica que casou fica disponível no campo
> `subtype` de cada evento, para ajuste fino.

`ssh_accept` é registrado para relatórios mas **não** é usado para suprimir strikes:
num IP compartilhado, um login bem-sucedido não prova que as outras tentativas
daquele IP são benignas. Anti-lockout de operador pertence à `allowlist` / a um
plano de gestão, não a "esse IP logou uma vez".
