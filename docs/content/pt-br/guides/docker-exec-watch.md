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

O watcher usa o mesmo socket docker e modelo de permissão do coletor de logs docker, assina só `exec_start` (um evento por exec, no momento em que realmente roda) e reconecta com backoff quando o docker reinicia.

## Acesso ao socket é uma decisão de privilégio

Alcançar a API de eventos do docker significa alcançar o socket do Docker
Engine, e esse acesso vem da participação no grupo `docker`. O grupo é a API
do Engine, não uma permissão de leitura: qualquer coisa que fale com ele pode
iniciar um container privilegiado, ou seja, virar root no host. Conceder isso
ao usuário de serviço ezyshield torna o daemon que faz parsing de log
equivalente a root.

Por isso o `ezyshield init` pergunta antes de conceder, tem não como padrão e
só pergunta quando a execução configura alguma fonte de log docker. Em
execuções scriptadas o opt-in é `--docker-group` (ou
`collectors.docker_group: true` no arquivo de respostas); o `--yes` sozinho
nunca concede. Sem o acesso, o watcher continua habilitado na configuração,
mas não observa nada.

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

Isso desabilita este watcher junto com os coletores de log docker. Veja a
[visão geral de segurança](../security/overview.md) para o que a concessão
significa e quais são as alternativas.

## Ajustando a lista de ignore

Rode um dia com a lista vazia e revise `ezyshield list --audit` (ou suas notificações): tudo que é periódico e esperado — health checks, containers de cron, tooling de backup, seu próprio CI — vai para o `ignore` por padrão de nome ou imagem. O que sobrar deve ser *raro e humano*: esse é o sinal.

Tudo que o docker reporta (nomes, imagens, comandos) é tratado como entrada não-confiável — capado e sanitizado em tempo de render como conteúdo de log.
