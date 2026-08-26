---
title: Nextcloud
description: Protegendo logins do Nextcloud via o nextcloud.log estruturado
order: 20
---

# Protegendo o Nextcloud

O Nextcloud escreve JSON estruturado no `nextcloud.log`, incluindo logins falhos com o endereço do cliente. O EzyShield parseia isso em eventos `nextcloud_auth_fail` (username capturado, capado, não-confiável) e traz `nextcloud_bruteforce` (5 falhas / 5 min, score 85) mais uma variante sustained de 1 h.

Entradas reconhecidas: `app: core` com `Login failed: '<user>' …`, e as linhas de login falho do app `admin_audit`.

## Coletores

```yaml
collectors:
  # bare metal / VM
  - kind: file
    path: /var/www/nextcloud/data/nextcloud.log   # roteia para o parser nextcloud pelo nome

  # docker (nome de container contendo "nextcloud" é roteado automaticamente)
  - kind: docker
    container: nextcloud-app-1
```

Se seu diretório de dados fica em outro lugar, aponte para ele; um nome de arquivo fora do padrão precisa de `parser: nextcloud` explícito.

## O requisito de `trusted_proxies` (leia isto)

O IP do evento vem do campo `remoteAddr` do próprio Nextcloud. **Atrás de um reverse proxy, `remoteAddr` só é o cliente quando o `trusted_proxies` do Nextcloud está configurado** (`config.php`):

```php
'trusted_proxies' => ['203.0.113.7'],   // o endereço do seu proxy
```

Sem isso, toda falha parece vir do proxy — banir isso bloquearia o próprio proxy. Confira em dry-run com `ezyshield watch`: se toda detecção mostra o mesmo endereço interno, corrija o `trusted_proxies` primeiro. (O EzyShield toma o `remoteAddr` como autoritativo, exatamente como o Nextcloud o apresenta — a resolução pertence à config do Nextcloud, mesma abordagem do trusted-proxy dos parsers web.)

O throttling de bruteforce embutido do Nextcloud continua útil em paralelo — o EzyShield adiciona o ban em nível de rede e a escada de strikes.

## Rollout

Dry-run primeiro, allowliste suas redes, observe um dia de decisões, então `ezyshield arm`.
