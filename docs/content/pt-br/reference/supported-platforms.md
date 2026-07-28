---
title: Plataformas suportadas
description: Distros e arquiteturas de CPU nas quais o EzyShield é testado, e como rodar a matriz de e2e no QEMU
order: 6
---

# Plataformas suportadas

O EzyShield é um único binário Go estático, sem dependências de runtime, então
roda em qualquer Linux 64-bit moderno com `nftables` e `systemd`. "Suportado"
aqui significa algo mais forte que "deveria rodar": cada célula verde na matriz
abaixo é exercitada pelo **round-trip armado ponta a ponta** — uma VM descartável
instala o EzyShield do jeito real (`curl … | sudo sh`), roda `ezyshield init`,
arma o daemon, bane um IP de teste e verifica que ele cai no set `nftables`
ativo. Esse é exatamente o caminho que um ban real percorre, então uma célula
verde significa que toda a cadeia daemon↔enforcer com separação de privilégios
funciona naquela plataforma.

A matriz cresce junto com o projeto e é atualizada a cada release.

## Matriz de suporte

Legenda:

- ✅ **verificado** — o e2e armado no QEMU passa ponta a ponta nesta plataforma
- 🟢 **host de produção** — validado adicionalmente em um servidor de produção (atacantes reais detectados e banidos)
- 🧪 **candidato** — conectado ao harness, ainda não confirmado verde
- ☐ **planejado** — no roadmap, ainda não executado

| Distro | Versão | x86_64 | arm64 |
|--------|--------|:------:|:-----:|
| Ubuntu | 24.04 LTS (noble) | ✅ | ☐ |
| Ubuntu | 25.04 (plucky) | 🟢 | ☐ |
| Debian | 12 (bookworm) | ✅ | ☐ |
| Debian | 13 (trixie) | ☐ | ☐ |
| AlmaLinux | 9 | 🧪 | 🧪 |
| Rocky Linux | 9 | 🧪 | 🧪 |

Rodadas x86_64 usam KVM; arm64 é emulado com `qemu-system-aarch64` (TCG) em um
host x86_64, ou acelerado com KVM em um runner arm64 nativo. Guests arm64 bootam
um binário cross-compilado (`GOARCH=arm64`) — o mesmo artefato que o pipeline de
release publica — então uma célula arm64 exercita o build arm64 de verdade, não
uma camada de tradução.

> **Família RHEL (Alma/Rocky) é candidata.** O harness conhece as cloud images,
> o usuário do guest, o sudoers via `wheel` e o conjunto de pacotes delas, mas o
> round-trip ainda não foi confirmado verde — trate essas células como
> best-effort até uma rodada acontecer.

## Rodando uma célula da matriz

O harness fica em [`scripts/qemu-e2e.sh`](https://github.com/evertramos/ezy-shield/blob/main/scripts/qemu-e2e.sh).
Ele compila o binário da sua working tree, serve por um servidor HTTP em
loopback, boota uma cloud image e roda o instalador contra ela — nada é
publicado, e nada toca o firewall do seu host (os passos destrutivos rodam
**dentro** do guest descartável).

Escolha uma distro e arquitetura com duas variáveis de ambiente:

```bash
# Preflight — imprime o plano resolvido (imagem, binário qemu, firmware) sem bootar
EZY_DISTRO=ubuntu2404 EZY_ARCH=amd64 scripts/qemu-e2e.sh config

# Round-trip armado completo: build → install → init → ban → assert
EZY_DISTRO=ubuntu2404 EZY_ARCH=amd64 scripts/qemu-e2e.sh up

# Inspecionar, re-rodar só as asserções, ou derrubar tudo
scripts/qemu-e2e.sh ssh
scripts/qemu-e2e.sh verify
scripts/qemu-e2e.sh down
```

`EZY_DISTRO` aceita `debian12`, `debian13`, `ubuntu2404`, `ubuntu2504`,
`alma9`, `rocky9`; `EZY_ARCH` aceita `amd64` (padrão: seu host) e `arm64`.
Para uma imagem fora da tabela, defina `EZY_IMG_URL`, `EZY_GUEST_USER` e
`EZY_FAMILY` (`deb` ou `rhel`) no lugar de `EZY_DISTRO`.

### Requisitos do host

| Alvo | Precisa de |
|------|-----------|
| guest x86_64 em host x86_64 | `qemu-system-x86` + `/dev/kvm` |
| guest arm64 em host x86_64 | `qemu-system-arm` + `qemu-efi-aarch64` (firmware UEFI); roda sob TCG — lento |
| guest arm64 em host arm64 | `qemu-system-arm` + `qemu-efi-aarch64` + `/dev/kvm` |

Todo alvo também precisa de `cloud-image-utils` (para `cloud-localds`),
`qemu-utils` (para `qemu-img`), `go`, `python3` e uma chave pública SSH
(`~/.ssh/id_rsa.pub` por padrão, ou aponte `EZY_SSH_KEY` para outra).

> ⚠️ `scripts/qemu-e2e.sh up` e o `scripts/e2e-install-test.sh` (rodado no guest)
> são **destrutivos por design** — criam o usuário `ezyshield`, instalam units
> do systemd e escrevem regras `nftables`. Rode-os apenas na VM descartável,
> nunca em uma workstation.

Veja o [guia de instalação](../getting-started/install.md) para os formatos de
pacote suportados e o caminho a partir do código-fonte.
