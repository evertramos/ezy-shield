---
title: Retenção de Dados
description: Janelas de retenção configuráveis e poda segura do banco
order: 7
---

# Retenção de Dados

O banco SQLite do EzyShield cresce sem limite em hosts sob ataque: cada strike, entrada de auditoria e chamada de IA adiciona uma linha. A poda por retenção mantém o banco limitado — e dá a você uma política de retenção por escrito para os dados pessoais que ele guarda (endereços IP são dados pessoais sob GDPR/LGPD; auditores perguntam por quanto tempo você os mantém).

A retenção é **opt-in**: sem uma seção `retention:` no `config.yaml`, nada é podado, nunca.

## Configuração

```yaml
retention:
  strikes: 730d      # histórico de strikes     (padrão 730d, piso 180d)
  audit: 365d        # jornal de auditoria      (padrão 365d, piso 90d)
  ai_usage: 90d      # contabilidade de IA      (padrão 90d,  piso 7d)
  # i_understand_the_risks: true       # permite janelas abaixo dos pisos (nunca abaixo de 24h)
  # audit_export_not_required: true    # OBRIGATÓRIO antes de qualquer deleção no audit_log
```

Durações aceitam a sintaxe do Go mais a unidade de dia (`30d`, `365d`, `2160h`). O literal `never` (ou `0`) desativa a poda daquela tabela. Valores abaixo dos pisos por tabela são rejeitados, a menos que `i_understand_the_risks: true` — e mesmo assim vale um mínimo absoluto de 24h.

## O que é podado — e o que nunca é

| Tabela | Janela | Semântica |
|---|---|---|
| `strikes` | `strikes` | Linhas mais antigas que a janela. O **strike mais recente de qualquer IP com ban ativo nunca é deletado**, independente da idade. |
| `offenders` | `strikes` | Apenas IPs cujo histórico de strikes *inteiro* envelheceu **e** que não têm ban ativo. |
| `audit_log` | `audit` | Linhas mais antigas que a janela — **somente** com `audit_export_not_required: true` (veja abaixo). |
| `ai_usage` | `ai_usage` | Linhas mais antigas que a janela. |
| `bans_active` | — | **Nunca tocada.** Bans ativos são estado de enforcement, não histórico. |
| `allowlist` | — | **Nunca tocada.** |

**O trade-off dos strikes.** O histórico de strikes alimenta a escalada de reincidentes. O contador de escalada (`total_strikes`) *não* é decrementado quando linhas antigas de strikes são podadas — um reincidente continua escalando. Mas quando o histórico inteiro de um IP envelhece (nenhum strike dentro da janela, nenhum ban ativo), a linha do offender é removida e a escalada recomeça do strike 1 no próximo ataque. Por isso o piso de `strikes` é 180 dias e o padrão, dois anos.

**O portão da auditoria.** O `audit_log` é o jornal de segurança append-only do EzyShield; deleção é a exceção, não a regra. Até existir um mecanismo de export que registre o que já foi arquivado (o forwarding SIEM é o caminho de arquivamento planejado), a poda da auditoria se recusa a rodar a menos que você defina explicitamente `audit_export_not_required: true` — reconhecendo que linhas serão deletadas sem nenhuma cópia em outro lugar. Cada execução de poda grava suas próprias linhas-resumo `retention_prune` (tabela, linhas deletadas, janela) *no* próprio audit log, então a deleção em si permanece rastreável.

## Quando roda

O daemon executa a poda uma vez por dia (primeira execução adiada e com jitter, para uma frota não fazer vacuum em sincronia). As deleções são em lotes (500 linhas por transação, cedendo a vez entre lotes), então um backlog grande nunca bloqueia a detecção. Após a poda, o arquivo do banco é compactado (`VACUUM`) apenas quando o espaço livre excede 25% do arquivo.

## Execução manual

```console
# Prévia: contagem de candidatos por tabela, não deleta nada
$ ezyshield maintenance prune --dry-run

# Execução real: exige confirmação explícita
$ ezyshield maintenance prune --yes
```

Ambas passam pelo socket de controle do daemon, então as permissões de arquivo e a trilha de auditoria são idênticas às do job diário.
