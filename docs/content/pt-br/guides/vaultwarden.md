---
title: Vaultwarden
description: Protegendo um cofre de senhas Vaultwarden de brute force
order: 19
---

# Protegendo o Vaultwarden

Um cofre de senhas é alvo prioritário de brute force. O EzyShield parseia o formato de log padrão do Vaultwarden e traz regras que banem adivinhação de credenciais e de 2FA.

## O que é detectado

Eventos `vaultwarden_auth_fail`, de dois formatos de linha:

- `Username or password is incorrect. Try again. IP: <ip>. Username: <user>.` — falhas de senha (username capturado, capado, tratado como não-confiável).
- `Invalid TOTP code! … IP: <ip>` — a variante de 2FA (campo `mfa=totp`).

Regras embutidas: `vaultwarden_bruteforce` (5 falhas / 5 min, score 85) e `vaultwarden_bruteforce_sustained` (10 / 1 h, score 80). Ajuste via drop-ins em `rules.d`.

## Coletores

Docker (o deployment comum — o parser reconhece containers com nome `*vaultwarden*` automaticamente, e desembrulha o formato json-file do docker):

```yaml
collectors:
  - kind: docker
    container: vaultwarden        # parser roteado pelo nome; ou adicione `parser: vaultwarden`
```

Por arquivo (`LOG_FILE=/var/log/vaultwarden.log`):

```yaml
  - kind: file
    path: /var/log/vaultwarden.log   # roteia para o parser vaultwarden pelo nome
```

## A ressalva do reverse proxy (leia isto)

O Vaultwarden quase sempre fica atrás de nginx/caddy/traefik. **Se o Vaultwarden não está configurado para confiar nos headers encaminhados pelo proxy, o IP no log dele é o do próprio proxy** — e bani-lo bloquearia o proxy (a allowlist/anti-lockout do EzyShield geralmente recusa localhost, mas um IP de rede docker pode não estar coberto).

- Correção certa: configure o suporte a reverse proxy do Vaultwarden (ex.: `IP_HEADER=X-Real-IP`) para o log carregar o IP real do cliente — aí este parser é a melhor fonte.
- Alternativa: pule o log do Vaultwarden e deixe o access log do **proxy** (parser nginx/caddy/traefik) fazer a detecção — brute force de login aparece lá como `POST /identity/connect/token` repetido, coberto pelas regras HTTP.
- Sanidade: rode em dry-run e acompanhe `ezyshield watch` — se toda detecção mostra o mesmo IP interno, você está vendo o proxy.

## Rollout

Como sempre: dry-run primeiro, allowliste suas redes, observe um dia de decisões, então `ezyshield arm`.
