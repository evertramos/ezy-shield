---
title: Docker Exec Watch
description: Visibilidade pós-exploração — todo `docker exec` nos seus containers, observado
order: 17
---

# Docker Exec Watch

Detecção baseada em log é cega para o que acontece **depois** de uma intrusão bem-sucedida. Em hosts docker existe uma fonte barata e de alto sinal: a API de eventos do docker emite um evento para cada `docker exec` num container. Um shell aberto dentro do seu container web às 3 da manhã é um forte indicador de pós-exploração que nenhum parser de log jamais verá.

## Escopo honesto (leia primeiro)

Isto é **detecção e visibilidade, não prevenção**: o EzyShield observa e reporta a atividade de exec; não bloqueia nem mata nada, e **nenhum ban deriva disso** — um exec não tem IP remoto para banir, e inventar um corromperia o histórico de ofensores. O que você recebe por exec observado:

- uma linha no `audit_log` (`docker_exec`, com container, imagem, usuário e o comando capado),
- um evento `docker_exec` ao vivo no `ezyshield watch`,
- uma notificação de severidade **warn** pelos seus canais normais (dedup/rate-limit valem).

## Habilitando

```yaml
# /etc/ezyshield/config.yaml
docker_exec:
  enabled: true
  ignore:                  # silencie o tooling legítimo
    - "healthcheck*"       # glob (path.Match) sobre nome do container ou imagem
    - cron                 # texto puro casa como substring
```

O watcher usa o mesmo socket docker e modelo de permissão do coletor de logs docker, assina só `exec_start` (um evento por exec, no momento em que realmente roda) e reconecta com backoff quando o docker reinicia.

## Ajustando a lista de ignore

Rode um dia com a lista vazia e revise `ezyshield list --audit` (ou suas notificações): tudo que é periódico e esperado — health checks, containers de cron, tooling de backup, seu próprio CI — vai para o `ignore` por padrão de nome ou imagem. O que sobrar deve ser *raro e humano*: esse é o sinal.

Tudo que o docker reporta (nomes, imagens, comandos) é tratado como entrada não-confiável — capado e sanitizado em tempo de render como conteúdo de log.
