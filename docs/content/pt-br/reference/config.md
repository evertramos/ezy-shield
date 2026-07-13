---
title: Referência de Config
description: Referência completa de config.yaml
order: 2
---

# Referência de Config

[Conteúdo de tradução em andamento - veja docs/content/en/reference/config.md para a versão em inglês]

Referência completa para `/etc/ezyshield/config.yaml`.

## Coletor SSH (nome do unit varia por distro)

O nome do unit systemd do SSH **depende da distro**: é `ssh` no Debian/Ubuntu e
`sshd` no RHEL/CentOS/Fedora/Rocky/Alma, Arch e SUSE. Use o nome que
`systemctl status <unit>` resolve no seu host — um alias que o `journalctl -u`
não reconhece coleta zero eventos.

```yaml
collectors:
  - kind: journald
    unit: ssh    # Debian/Ubuntu; use "sshd" no RHEL/CentOS/Arch/SUSE
```

Para ler o SSH de um arquivo em vez do journald, aponte para o log de auth da
sua distro — `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (família
RHEL). Os dois formatos de timestamp são aceitos: o legado (`Jan  1 12:00:00`) e
o ISO-8601 moderno (`2026-07-13T22:57:35+00:00`).

> **Configure apenas um coletor de SSH por host** — journald **ou** o arquivo que
> ele alimenta, nunca os dois. Ler ambos ingere cada evento duas vezes, o que
> conta em dobro para os limiares de detecção. (Um IP já banido nunca é banido de
> novo, então isso nunca gera bans duplicados, apenas detecção mais cedo.)

[Traduções a seguir...]
