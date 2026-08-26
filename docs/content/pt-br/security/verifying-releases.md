---
title: Verificando Releases
description: Verifique criptograficamente os artefatos de release do EzyShield com cosign
order: 2
---

# Verificando Releases

Toda release do EzyShield assina seu `checksums.txt` com
[cosign keyless signing](https://docs.sigstore.dev/cosign/verifying/verify/):
a assinatura é produzida dentro do workflow de release do GitHub Actions
usando a identidade OIDC dele, registrada no log público de transparência do
Sigstore, e anexada à release como `checksums.txt.sig` (assinatura) e
`checksums.txt.pem` (certificado). Não existe chave privada para roubar ou
gerenciar — a âncora de confiança é a própria identidade do workflow.

Como o `checksums.txt` carrega o SHA-256 de cada artefato, uma assinatura
verificada autentica transitivamente todos eles: binários crus, tarballs e
pacotes deb/rpm. Cada artefato também acompanha um SBOM SPDX
(`<artefato>.spdx.json`) gerado com [syft](https://github.com/anchore/syft).

## O que a verificação prova

Um `cosign verify-blob` bem-sucedido prova que o `checksums.txt` foi
produzido pelo workflow `release.yaml` **deste repositório**, na
infraestrutura do GitHub — não por um token do GitHub comprometido, uma
release sequestrada ou um mirror. Não prova que o código-fonte é livre de
bugs; prova que os artefatos em suas mãos são os que aquele workflow gerou.

## Verificar uma release

```bash
VERSION=v0.1.0   # a tag que você está verificando
BASE=https://github.com/evertramos/ezy-shield/releases/download/${VERSION}

curl -sfLO "${BASE}/checksums.txt"
curl -sfLO "${BASE}/checksums.txt.sig"
curl -sfLO "${BASE}/checksums.txt.pem"

cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    '^https://github\.com/evertramos/ezy-shield/\.github/workflows/release\.yaml@refs/(tags/v[0-9][^ ]*|heads/(main|dev))$' \
  checksums.txt
```

Saída esperada: `Verified OK`.

O regexp de identidade fixa **repositório e arquivo do workflow**. A parte
do ref aceita os dois caminhos de disparo de release: uma tag enviada
(`refs/tags/vX.Y.Z`) e um `workflow_dispatch` a partir de `main` (estável)
ou `dev` (release candidates) — no caso do dispatch, o certificado carrega a
branch em que o workflow rodou, não a tag que ele criou.

Depois, confira o artefato baixado contra o checksums já verificado:

```bash
curl -sfLO "${BASE}/ezyshield-linux-amd64"
sha256sum --check --ignore-missing checksums.txt
```

## Verificar a imagem de container

A imagem multi-arch `ghcr.io/evertramos/ezyshield` é assinada com a mesma
identidade keyless de workflow do `checksums.txt`. A mesma imagem também é
espelhada no Docker Hub — `docker pull evertramos/ezyshield` funciona sem
apontar para o ghcr.io; os dois registries recebem o mesmo manifest de um
único build, e prereleases nunca movem o `latest` em nenhum deles. A
assinatura fica no registry, ao lado da imagem, então o cosign busca
sozinho tudo de que precisa:

```bash
VERSION=v0.1.0   # a release que você está verificando (tags de imagem não têm o "v")
cosign verify \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    '^https://github\.com/evertramos/ezy-shield/\.github/workflows/release\.yaml@refs/(tags/v[0-9][^ ]*|heads/(main|dev))$' \
  "ghcr.io/evertramos/ezyshield:${VERSION#v}"
```

Uma execução bem-sucedida lista as checagens feitas (assinatura, log de
transparência, identidade do certificado) e imprime o payload assinado
verificado em JSON. O cosign resolve a tag para o **digest** da imagem e
verifica contra ele — uma tag movida ou re-publicada falha a verificação.
Para a fixação mais forte, baixe e execute pelo digest —
`ghcr.io/evertramos/ezyshield@sha256:<digest>` — usando o digest que a
saída da verificação reporta.

A imagem também carrega um **SBOM SPDX** por plataforma, anexado no build
como atestação do BuildKit (gerado pelo scanner syft dentro do build de
release — a contraparte, no container, dos assets `.spdx.json` da release).
Inspecione com:

```bash
docker buildx imagetools inspect "ghcr.io/evertramos/ezyshield:${VERSION#v}" \
  --format '{{ json .SBOM }}'
```

## Notas

- Releases publicadas **antes** da assinatura existir (release candidates
  iniciais da v0.1.0) não têm os assets `.sig`/`.pem`; para essas, a
  integridade repousa apenas no TLS com `github.com`. Da mesma forma,
  imagens de container publicadas antes da assinatura de imagem existir não
  carregam assinatura cosign nem atestação de SBOM — o `cosign verify` falha
  nelas por design.
- O script de instalação `get.ezyshield.com` executa essa mesma verificação
  automaticamente quando o `cosign` está instalado no host, e imprime um
  aviso (sem falhar) quando não está.
- O `ezyshield update` é **mais estrito que o script de instalação**: antes de
  confiar no `checksums.txt` ele verifica a assinatura contra a identidade
  fixada do workflow e **falha fechado** — assets `.sig`/`.pem` ausentes,
  `cosign` não instalado ou qualquer divergência na verificação abortam o
  update (o updater roda como root, então um atacante capaz de remover os
  assets de assinatura não pode rebaixá-lo a confiança sem assinatura). O
  `--allow-unsigned` é o opt-out explícito para os dois casos de pré-requisito
  ausente (release anterior à assinatura, host sem `cosign`); uma verificação
  com falha aborta mesmo com a flag.
- Pacotes deb/rpm instalados pelo repositório de pacotes são adicionalmente
  verificados por GPG pelo apt/dnf contra a chave de assinatura do
  repositório.
- SBOMs: baixe `<artefato>.spdx.json` da página da release para auditar o
  grafo exato de módulos com que um artefato foi construído (ex.: alimente
  `grype`/`osv-scanner` para varredura de vulnerabilidades).
