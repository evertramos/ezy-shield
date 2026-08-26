---
title: Keycloak
description: Banindo brute force de login no Keycloak via eventos LOGIN_ERROR
order: 16
---

# Protegendo o Keycloak

O Keycloak pode logar eventos de login pelo logger `org.keycloak.events`; linhas `LOGIN_ERROR` carregam o `ipAddress` do cliente. O EzyShield as transforma em eventos `keycloak_auth_fail` (realm/username capturados, capados, não-confiáveis) e traz `keycloak_bruteforce` (5 falhas / 5 min, score 85) mais uma variante sustained de 1 h.

## Habilite o log de eventos no Keycloak (obrigatório)

O Keycloak **não** loga eventos de login por padrão. Duas partes:

1. **O event listener** — no admin console: *Realm settings → Events → Event listeners*, garanta que `jboss-logging` está presente (está, por padrão). *Save events* NÃO é necessário — o logger dispara de qualquer forma.
2. **O log level** — a categoria `org.keycloak.events` loga sucessos em DEBUG mas `LOGIN_ERROR` em WARN. Garanta que seu nível mostra isso (o WARN padrão já mostra):

```bash
# Keycloak quarkus (conf/keycloak.conf ou CLI):
log-level=INFO,org.keycloak.events:WARN
```

Sanidade: falhe um login e confirme que uma linha `type=LOGIN_ERROR, … ipAddress=…` chega no seu journal/log de container.

## Coletores

```yaml
collectors:
  # serviço systemd
  - kind: journald
    unit: keycloak

  # docker (nome de container contendo "keycloak" é roteado automaticamente)
  - kind: docker
    container: keycloak
```

Fonte por arquivo também funciona (`keycloak.log`, ou qualquer caminho com `parser: keycloak`).

## Nota de reverse proxy

`ipAddress` é o que o Keycloak vê. Atrás de proxy, configure os headers de proxy do Keycloak (`proxy-headers=xforwarded` no Quarkus) para ele resolver o cliente real — senão toda falha parece vir do proxy. Verifique em dry-run com `ezyshield watch` antes de armar.

## Rollout

Dry-run primeiro, allowliste suas redes, observe um dia de decisões, então `ezyshield arm`.
