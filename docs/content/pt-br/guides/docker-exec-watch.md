---
title: Docker Exec Watch
description: Visibilidade pós-exploração — todo `docker exec` nos seus containers, observado
order: 22
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

O watcher usa o mesmo endpoint do Engine e modelo de permissão do coletor de logs docker, assina só `exec_start` (um evento por exec, no momento em que realmente roda) e reconecta com backoff quando o docker reinicia.

## Acesso ao Engine é uma decisão de privilégio

Alcançar a API de eventos do docker significa alcançar a API do Docker Engine.
O endpoint é o [`docker.host`](../reference/config.md), compartilhado com os
coletores de log docker, e há duas formas de servi-lo — um coletor baseado em
arquivo não é uma delas aqui, porque eventos não têm equivalente em arquivo.

**Um proxy somente-leitura do socket (recomendado).** Um proxy com filtro na
frente do socket do Engine, publicado em `127.0.0.1`, serve eventos e logs de
container e recusa criação de container, exec e mounts:

```yaml
# /etc/ezyshield/config.yaml
docker:
  host: tcp://127.0.0.1:2375
```

O proxy precisa expor **ambos** `CONTAINERS` e `EVENTS` — este watcher precisa
de `GET /events` — e nada mais. O trecho de compose está em
[Docker + nginx + WordPress](docker-nginx-wordpress.md); o `ezyshield doctor`
verifica se o endpoint responde `GET /_ping` e recusa
`POST /containers/create`.

**O grupo `docker` (último recurso).** O acesso ao socket do Engine vem da
participação nesse grupo. O grupo é a API do Engine, não uma permissão de
leitura: qualquer coisa que fale com ele pode iniciar um container
privilegiado, ou seja, virar root no host. Conceder isso ao usuário de serviço
ezyshield torna o daemon que faz parsing de log equivalente a root.

Por isso o `ezyshield init` pergunta antes de conceder, tem não como padrão e
só pergunta quando a execução configura alguma fonte de log docker. Em
execuções scriptadas o opt-in é `--docker-group` (ou
`collectors.docker_group: true` no arquivo de respostas); o `--yes` sozinho
nunca concede. Sem nenhum dos dois tipos de acesso, o watcher continua
habilitado na configuração, mas não observa nada.

Uma instalação provisionada antes pode já carregar a participação — tirar a
concessão do `init` não a revoga, e uma atualização de pacote também não.
Verifique:

```bash
ezyshield doctor          # avisa quando o usuário de serviço está no grupo docker
getent group docker       # o ezyshield aparece na lista?
```

Para revogar:

```bash
sudo gpasswd -d ezyshield docker
sudo systemctl restart ezyshield
```

Isso desabilita este watcher junto com os coletores de log docker, a menos que
o `docker.host` aponte para um proxy somente-leitura. Veja a
[visão geral de segurança](../security/overview.md) para o que a concessão
significa e quais são as alternativas.

## Ajustando a lista de ignore

Rode um dia com a lista vazia e revise `ezyshield list --audit` (ou suas notificações): tudo que é periódico e esperado — health checks, containers de cron, tooling de backup, seu próprio CI — vai para o `ignore` por padrão de nome ou imagem. O que sobrar deve ser *raro e humano*: esse é o sinal.

Tudo que o docker reporta (nomes, imagens, comandos) é tratado como entrada não-confiável — capado e sanitizado em tempo de render como conteúdo de log.
