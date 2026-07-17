---
title: Referência de Config
description: Referência completa de config.yaml
order: 2
---

# Referência de Config

[Conteúdo de tradução em andamento - veja docs/content/en/reference/config.md para a versão em inglês]

> `ezyshield init` e os wizards `ezyshield config <componente>` escrevem em `/etc/ezyshield` e precisam de `sudo` — falham imediatamente com a dica antes de qualquer pergunta.

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

## enrich (GeoIP/ASN)

Enriquecimento GeoIP/ASN — habilita `block_countries` / `block_asns` no policy e as colunas de país/ASN em `list` e `report`. Opcional: sem a seção `enrich:` o daemon roda normalmente com enriquecimento vazio (sem país/ASN em lugar nenhum, e essas chaves de policy nunca casam).

| Campo | Descrição |
|-------|-----------|
| `db_path` | caminho do `GeoLite2-Country.mmdb` |
| `asn_path` | caminho do `GeoLite2-ASN.mmdb` |
| `auto_update` | o daemon baixa e atualiza os bancos sozinho (semanalmente) |
| `license_key` | referência `env:VARNAME` para uma license key da MaxMind — obrigatória com `auto_update: true`; valores inline são rejeitados |

O caminho mais fácil é o wizard, que conduz por tudo isso:

```bash
sudo ezyshield config enrich maxmind
sudo systemctl restart ezyshield
```

**De onde vêm os bancos.** O EzyShield usa os bancos gratuitos GeoLite2 da MaxMind, que exigem uma conta (gratuita): [cadastre-se](https://www.maxmind.com/en/geolite2/signup) e gere uma license key em *Manage License Keys*. Com `auto_update: true` o daemon baixa os dois bancos sozinho no startup quando os arquivos estão ausentes e os atualiza semanalmente — você nunca manuseia os arquivos:

```yaml
enrich:
  db_path: /var/lib/ezyshield/GeoLite2-Country.mmdb
  asn_path: /var/lib/ezyshield/GeoLite2-ASN.mmdb
  auto_update: true
  license_key: env:MAXMIND_LICENSE_KEY
```

A chave é um segredo como qualquer outro: coloque `MAXMIND_LICENSE_KEY=...` em `/etc/ezyshield/.env` (modo 0600 — o wizard faz isso por você) e referencie como `env:MAXMIND_LICENSE_KEY`. Ela só é usada na URL de download e nunca é logada.

**Alternativa manual.** Com `auto_update: false` nenhuma chave é necessária em runtime: baixe `GeoLite2-Country.mmdb` e `GeoLite2-ASN.mmdb` da sua conta MaxMind (ou espelhe de um host que já os tenha) e coloque nos caminhos configurados. Arquivos ausentes ou ilegíveis não são erro — o daemon loga um aviso e roda com enriquecimento vazio até eles aparecerem.

[Traduções a seguir...]
