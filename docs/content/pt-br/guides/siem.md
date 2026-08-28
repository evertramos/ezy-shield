---
title: Encaminhamento SIEM
description: Envie toda ação auditada para Wazuh, Splunk ou qualquer coletor syslog
order: 17
---

# Encaminhamento SIEM

O EzyShield pode encaminhar **toda ação auditada** — bans, bans em
dry-run, unbans, expirações, mudanças de allowlist, arm/disarm,
start/stop do daemon — para um ou mais endpoints SIEM. Somente saída
(nenhum listener novo), assíncrono e limitado: um SIEM lento ou morto
nunca bloqueia nem desestabiliza o pipeline de decisão. Quando a fila de
um sink (padrão 1024 eventos) enche, os eventos **mais antigos** são
descartados e contados.

```yaml
# /etc/ezyshield/config.yaml
siem:
  - name: wazuh
    address: tls://siem.example.com:6514
    format: rfc5424
    ca_file: /etc/ezyshield/siem-ca.pem   # pin de CA opcional
  - name: copia-auditoria
    address: file:///var/log/ezyshield-forward.log
    format: json
```

## Transportes

| Scheme | Transporte | Framing |
|---|---|---|
| `tls://host:porta` | TCP + TLS (ServerName verificado; `ca_file` opcional) | octet counting RFC 6587 para `rfc5424`, newline para `json`/`cef` |
| `tcp://host:porta` | TCP em texto claro (**exige `allow_insecure_transport: true`**) | igual ao tls |
| `udp://host:porta` | UDP em texto claro (**exige `allow_insecure_transport: true`**) | um datagrama por evento |
| `uds:///caminho` | socket unix (stream, com fallback para datagrama) | stream com framing, datagrama sem |
| `file:///caminho` | append em arquivo local | uma linha por evento |

Transportes em texto claro são recusados no load do config a menos que
você defina explicitamente `allow_insecure_transport: true`, e o
`ezyshield doctor` continua avisando alto — eventos de auditoria carregam
IPs e motivos de regra que podem citar conteúdo de log. A entrega
reconecta com backoff limitado; no shutdown há uma tentativa de flush com
prazo.

## Tipos de evento

O filtro `events:` (vazio = todos) casa com os nomes das operações de
auditoria: `ban`, `dry_ban`, `unban`, `expire`, `allow`, `unallow`,
`ban_refused`, `arm`, `disarm`, mais os eventos de ciclo de vida
sintetizados `daemon_start` e `daemon_stop`. (A lista segue o audit log;
operações auditadas novas são encaminhadas automaticamente.)

## Receita Wazuh

O Wazuh ingere syslog RFC 5424 nativamente. No manager, habilite um
remote de syslog (`/var/ossec/etc/ossec.conf`):

```xml
<remote>
  <connection>syslog</connection>
  <port>6514</port>
  <protocol>tcp</protocol>
  <allowed-ips>203.0.113.0/24</allowed-ips>  <!-- IP do seu servidor -->
</remote>
```

Coloque TLS na frente (o remote de syslog do Wazuh é texto claro) com um
terminador stunnel/nginx stream, ou — apenas em rede privada confiável —
use `tcp://` com `allow_insecure_transport: true`. Lado EzyShield:

```yaml
siem:
  - name: wazuh
    address: tls://wazuh.internal:6514
    format: rfc5424
```

Os eventos chegam como syslog padrão com structured data
(`[ezyShield@32473 action="ban" ip="..." rule="..." ...]`), prontos para
decoders/rules do Wazuh.

## Receita Splunk

Use um Universal Forwarder ou um TCP input do indexer. Para TCP input com
TLS (Settings → Data inputs → TCP → with SSL), lado EzyShield:

```yaml
siem:
  - name: splunk
    address: tls://splunk.internal:5140
    format: json
```

Defina o sourcetype do input como `_json` (ou
`sourcetype = ezyshield:audit`) — os eventos JSON são objetos planos com
nomes estáveis (`schema_version`, `action`, `ip`, `rule`, `score`,
`strike`, `ttl_seconds`, `actor`, `node`). Alternativa: escreva num sink
de arquivo (`file:///var/log/ezyshield-forward.log`) e deixe o Universal
Forwarder monitorar o arquivo.

## Verificando

```bash
sudo ezyshield doctor    # por sink: aviso de segurança de transporte, alcançabilidade (não-fatal)
```

Problemas de alcançabilidade são avisos, não falhas — o EzyShield segue
protegendo e armazenando na fila independentemente da saúde do SIEM.
