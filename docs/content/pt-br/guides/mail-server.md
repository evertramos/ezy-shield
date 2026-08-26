---
title: Servidores de Mail
description: Protegendo Postfix e Dovecot de brute force SMTP/IMAP
order: 13
---

# Protegendo Servidores de Mail

Serviços de mail estão entre os mais brute-forçados da internet. O EzyShield parseia logs do smtpd do Postfix e de login do Dovecot e traz regras padrão que banem brute force de credenciais, sondagem de open relay e abuso de conexão — com a mesma escada de strikes, supremacia da allowlist e dry-run por padrão de todo o resto.

## O que é detectado

| Evento | Emitido por | Significado |
|---|---|---|
| `smtp_auth_fail` | parser postfix | falha de autenticação SASL LOGIN/PLAIN/… |
| `smtp_relay_denied` | parser postfix | `NOQUEUE: reject … Relay access denied` (rejects comuns de usuário inexistente ficam mudos) |
| `smtp_abuse` | parser postfix | "too many errors after RCPT", "lost connection after AUTH" |
| `imap_auth_fail` | parser dovecot | IMAP/POP3 `(auth failed, N attempts …)` |
| `imap_probe` | parser dovecot | `Disconnected (no auth attempts …)` — sondagem sem credenciais, sinal baixo |

Regras embutidas (ajuste via drop-ins em `rules.d`, mesclados por nome):

| Regra | Janela | Threshold | O que pega |
|---|---|---|---|
| `mail_bruteforce` | 5 min | 5 | adivinhação de credenciais SMTP + IMAP/POP3 (kinds combinados) |
| `mail_relay_probe` | 5 min | 3 | sondagem de open relay |
| `mail_bruteforce_sustained` | 1 h | 10 | falhas low & slow + abuso de conexão |
| `mail_probe_aggressive` | — | — | **desabilitada por padrão** — conta `imap_probe`; descomente no rules.yaml/rules.d se o ruído de sondas incomodar (maior risco de FP) |

## Postfix / Dovecot bare-metal

As units journald são as fontes recomendadas (funcionam independente de qual arquivo o syslog escreve):

```yaml
# /etc/ezyshield/config.yaml
collectors:
  - kind: journald
    unit: postfix        # postfix@- em alguns Debians: use a unit que o systemctl mostra
  - kind: journald
    unit: dovecot
```

Alternativa por arquivo: `mail.log`/`maillog` roteia para o parser **postfix** automaticamente. Linhas do Dovecot no mesmo arquivo compartilhado precisam da própria fonte — a unit journald acima, ou um `log_path = /var/log/dovecot.log` dedicado no Dovecot mais:

```yaml
  - kind: file
    path: /var/log/dovecot.log     # roteia para o parser dovecot pelo nome
```

## Mailcow / stacks em container

Postfix e Dovecot no mailcow logam via docker. Aponte coletores docker para os containers e force o parser:

```yaml
collectors:
  - kind: docker
    container: mailcowdockerized-postfix-mailcow-1
    parser: postfix
  - kind: docker
    container: mailcowdockerized-dovecot-mailcow-1
    parser: dovecot
```

(Os parsers desembrulham o formato json-file do docker automaticamente.)

## Rollout

Igual a tudo no EzyShield: comece em **dry-run**, acompanhe `ezyshield watch --kind dry_ban` com um dia de tráfego real, allowliste suas próprias redes (`policy.yaml` ou `ezyshield allow`), então `ezyshield arm`. Um cliente de mail banido é recuperável — o primeiro strike dura 5 minutos.
