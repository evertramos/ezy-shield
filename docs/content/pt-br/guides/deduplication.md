---
title: Deduplicação de Strikes
description: Entenda como EzyShield evita bans redundantes
order: 2
---

# Deduplicação de Banimentos Ativos — EzyShield

## Visão geral

A partir da issue #28, `Engine.Decide` suprime gravações redundantes de
strikes e chamadas RPC ao enforcer quando o IP alvo já possui um banimento
ativo em `bans_active`.

## Semântica

Um **strike** representa um *episódio de ataque*, não uma requisição individual.
O guard de deduplicação reforça esse limite:

| Cenário | Comportamento do motor |
|---|---|
| IP novo cruza `ban_threshold` | Strike #1 registrado; banimento de 5 minutos aplicado |
| Mesmo IP re-atinge enquanto o ban está ativo | Suprimido: nenhum novo strike, nenhum RPC ao enforcer; apenas `offenders.last_seen` é atualizado |
| Banimento ativo expira (`ExpireBans`) | Próxima detecção registra strike #2 (banimento de 1 hora) |
| IP atinge banimento permanente (strike #5, TTL=0) | Suprimido para sempre — registros permanentes não são varridos pelo `ExpireBans` |
| Reinicialização do daemon | Supressão retomada a partir de `bans_active` (persistido no SQLite); nenhum estado em memória necessário |

## Valores do campo `Op` nas ações

| Valor de `Op` | Significado |
|---|---|
| `"ban"` | Strike registrado; RPC ao enforcer emitido; banimento ativo |
| `"dry_ban"` | Seria banido; `armed=false`; sem gravações |
| `"already_banned"` | Suprimido: IP já está em `bans_active`; apenas `last_seen` atualizado |
| `"notify_only"` | Score na faixa de observação; sem banimento |
| `"record"` | Abaixo do limiar de observação, ou na allowlist |

## Impacto em `offenders.total_strikes`

Antes desta correção, `total_strikes` contava requisições maliciosas brutas
(por exemplo, 60 para um burst de scanner de 66 segundos a 1 req/s). Com a
deduplicação, `total_strikes` conta episódios distintos de ataque — o número
de vezes que um IP retornou e atacou após um período de resfriamento. Isso
torna o campo um indicador significativo de reincidência.

## Camadas de Detecção: Burst vs Sustentado

O EzyShield usa um modelo de detecção em duas camadas para capturar tanto atacantes rápidos quanto scanners "baixo e lento" (low & slow):

### Camada Burst (janela de 60 segundos)

**Objetivo**: Capturar ataques rápidos em rajadas concentradas.

**Exemplos**:
- Scanner WordPress atingindo `/wp-login.php` 3+ vezes em 60 segundos
- Brute force SSH: 5+ falhas de login em 60 segundos
- Scanner HTTP: 20+ respostas 404 em 60 segundos

**Ajuste**: Limiares conservadores otimizados para alta confiança. Falsos positivos são raros.

### Camada Sustentada (janela de 1 hora)

**Objetivo**: Capturar atacantes que distribuem suas sondagens ao longo de horas (estratégia "low & slow").

**Exemplo real** (Issue #48): Um atacante mirando WordPress com 30 tentativas de login distribuídas ao longo de 6 horas em rajadas de 2–3 hits. Cada rajada fica abaixo do limiar da camada burst (3 hits/min), mas acumula 10+ hits em 1 hora, acionando a detecção sustentada.

**Exemplos**:
- WordPress: 10+ hits em `/wp-login` distribuídos ao longo de 1 hora
- Abuso XML-RPC: 8+ sondagens em `/xmlrpc.php` ao longo de 1 hora
- Scanning HTTP: 60+ 404s distintos ao longo de 1 hora
- SSH: 15+ logins falhados ao longo de 1 hora

**Ajuste**: Limiares definidos conservadoramente para evitar atividade de usuários legítimos:
- Um administrador que faz login no WordPress 3–4 vezes por hora não acionará a regra
- Um script de backup automatizado fazendo requisições periódicas não acionará
- Crawlers legítimos com 404 ocasionais não acionarão

### Como Funcionam Juntas

1. **Regra burst ativa primeiro**: Captura sondadores agressivos imediatamente
2. **Regra sustentada ativa depois**: Captura atacantes pacientes que escapam
3. **Deduplicação previne duplo-banimento**: Uma vez que um IP está em `bans_active`, hits sustentados são suprimidos (veja Deduplicação de Banimentos Ativos acima)

### Ajustando Limiares

Para customizar os limiares, edite `configs/rules.yaml` e ajuste os campos `window` e `threshold`:

```yaml
- name: http_wp_probe_sustained
  window: 3600s        # 1 hora
  threshold: 10        # ajuste para seu ambiente
  score: 75
```

**Diretrizes**:
- Aumente o limiar se usuários legítimos estão acionando a regra
- Diminua o limiar se você está vendo ataques low & slow escapando da detecção
- Mantenha limiares burst e sustentado separados; eles capturam padrões diferentes

## Detecção de Sondagens Exploit (Veredicto Imediato)

O EzyShield inclui uma terceira camada de detecção para caminhos RCE e exploit conhecidos que têm **uso legítimo zero**:

### Regra http_rce_probe

**Objetivo**: Detecção imediata de caminhos de exploit conhecidos.

**Limiar**: 1 (uma única requisição dispara)  
**Score**: 95 (ultrapassa a faixa ambígua; regras sempre vençam)  
**Categoria**: `exploit_probe`

**Caminhos detectados**: `phpunit`, `.git`, `.aws`, `cgi-bin`, endpoints actuator, variantes `.env`, shells de plugins WordPress, estado Terraform, configs de banco de dados, etc.

**Por que limiar=1**: Estes caminhos têm zero uso legítimo em produção. Uma única requisição a `/.git/config` ou `/admin.php` é sempre suspeita.

**Por que score=95**: Colocado acima da faixa ambígua (0–90), então o motor de decisão nunca consulta IA — o veredicto de regras é final.

**Sem risco de duplo-banimento**: Sondagens exploit disparam instantaneamente com score=95, então entram em `bans_active` antes de qualquer regra de burst. Hits subsequentes são suprimidos por deduplicação.

### Detecção relacionada a exploits

Outras regras visando erros de baixa frequência que podem indicar scanning:
- `http_scanner_400`: 10+ requisições malformadas (limiar=10, score=60)
- `http_scanner_503`: 15+ respostas de serviço indisponível (limiar=15, score=65)

Estas operam na camada burst e permitem mais requisições antes de disparar, já que ocasionais 400/503 são legítimas.

## Referências

- Issue #28: implementação e evidências do kylian-s (03–04/07/2026)
- Issue #47: suporte contains_any e detecção de sondagens exploit (08/07/2026)
- Issue #48: regras sustentadas para detecção low & slow (08/07/2026)
- `internal/decision/engine.go`: `Engine.Decide` — guard de banimento ativo
- `internal/store/store.go`: `HasActiveBan`, `BumpLastSeen`
- `docs/content/pt-br/getting-started/index.md`: tabela de strikes e semântica de deduplicação
