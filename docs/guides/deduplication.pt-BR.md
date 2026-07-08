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

## Referências

- Issue #28: implementação e evidências do kylian-s (03–04/07/2026)
- `internal/decision/engine.go`: `Engine.Decide` — guard de banimento ativo
- `internal/store/store.go`: `HasActiveBan`, `BumpLastSeen`
- `docs/QUICKSTART.md`: tabela de strikes e semântica de deduplicação
