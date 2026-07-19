---
title: Instalando EzyShield
description: Instale a partir de release, source ou espelho air-gapped
order: 2
---

# Instalando EzyShield

Este guia cobre todas as formas de instalar EzyShield: a partir de uma versão pré-compilada, uma versão específica ou candidata a lançamento, um espelho customizado, ou a partir do código-fonte.

---

## Instalar via gerenciador de pacotes (apt / dnf)

Os pacotes nativos trazem os binários, as units do systemd, o usuário de
serviço `ezyshield` e upgrades limpos. Os metadados do repositório são
assinados com GPG; releases estáveis ficam na suite `stable`, release
candidates em `testing`.

**Debian / Ubuntu:**

```bash
curl -fsSL https://packages.ezyshield.com/ezyshield.asc | sudo gpg --dearmor -o /usr/share/keyrings/ezyshield.gpg
echo "deb [signed-by=/usr/share/keyrings/ezyshield.gpg] https://packages.ezyshield.com/apt stable main" | sudo tee /etc/apt/sources.list.d/ezyshield.list
sudo apt update && sudo apt install ezyshield
```

**RHEL / Rocky / Alma:**

```bash
sudo tee /etc/yum.repos.d/ezyshield.repo <<'EOF'
[ezyshield]
name=EzyShield
baseurl=https://packages.ezyshield.com/rpm/stable/$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://packages.ezyshield.com/ezyshield.asc
EOF
sudo dnf install ezyshield
```

> `repo_gpgcheck=1` valida os metadados assinados do repositório, que por sua
> vez fixam o SHA-256 de cada pacote — a integridade é coberta de ponta a
> ponta. Assinatura por pacote rpm chega com o futuro trabalho de assinatura
> de artefatos, quando `gpgcheck=1` vira o padrão documentado.

Fingerprint da chave de assinatura (confira após importar com `gpg --show-keys`):

```
810E EEB0 1802 38F7 E800  4A9E E1AD 3D15 A121 3612
```

Para acompanhar release candidates, troque `stable` por `testing` em
qualquer dos snippets. Os pacotes **não** habilitam nem iniciam serviço
algum — rode `sudo ezyshield init` depois de instalar.

---

## Instalação rápida (última versão estável)

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

Isso faz download da última versão estável, verifica checksums e instala os binários em `/usr/local/bin/`.

---

## Instalando uma versão específica ou candidata a lançamento

Se você quer uma versão específica (incluindo candidatos a lançamento como `v0.3.0-rc.1`), configure `EZYSHIELD_VERSION`:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.3.0-rc.1 sh
```

A versão deve começar com `v`. As versões disponíveis estão listadas em [github.com/evertramos/ezy-shield/releases](https://github.com/evertramos/ezy-shield/releases).

---

## Instalando a partir de um espelho customizado (ambientes isolados)

Para instalações em ambientes isolados ou CI, aponte o instalador para um espelho customizado com ambos os binários e `checksums.txt`:

```bash
curl -sfL https://get.ezyshield.com | EZYSHIELD_BASE_URL=https://mirror.exemplo.com/ezyshield/v0.3.0 sudo sh
```

O script irá:
1. Fazer download de `checksums.txt`, `ezyshield-linux-amd64` e `ezyshield-enforcer-linux-amd64` (ou arquitetura apropriada)
2. Verificar checksums SHA-256
3. Instalar em `/usr/local/bin/`

**Nota de segurança:** Checksums protegem contra corrupção na transferência, mas NÃO autenticam um espelho comprometido. Use isso apenas para espelhos confiáveis ou artefatos que você já tenha validado.

Ao usar `EZYSHIELD_BASE_URL`, você também pode configurar `EZYSHIELD_VERSION` para sua própria versão:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=internal-rc1 EZYSHIELD_BASE_URL=https://mirror.exemplo.com/ezyshield/v0.3.0 sh
```

---

## Compilando a partir do código-fonte

Se binários pré-compilados não estão disponíveis para sua plataforma, ou se você prefere compilar você mesmo:

```bash
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
make build
sudo install -m 755 bin/ezyshield /usr/local/bin/
sudo install -m 755 bin/ezyshield-enforcer /usr/local/bin/
```

---

## Atualizando para uma nova versão

**Instalado via apt / dnf** (recomendado — atualizações chegam junto com as do sistema):

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade ezyshield

# RHEL / Rocky / Alma
sudo dnf upgrade ezyshield
```

Os arquivos de configuração em `/etc/ezyshield` nunca são tocados pelo upgrade de pacote. Reinicie os serviços depois:

```bash
sudo systemctl restart ezyshield-enforcer ezyshield
```

**Instalado via script** (binários em `/usr/local/bin`) — rode o script de novo; ele substitui os binários no lugar:

```bash
# Última versão estável
curl -sfL https://get.ezyshield.com | sudo sh

# Ou versão específica
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0 sh

sudo systemctl restart ezyshield-enforcer ezyshield
```

---

## Desinstalando

```bash
sudo rm /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer

# Também remover configuração (se desejado)
sudo rm -rf /etc/ezyshield
```

---

## Referência de variáveis de ambiente

| Variável | Propósito | Exemplo |
|----------|-----------|---------|
| `EZYSHIELD_VERSION` | Instalar uma versão específica (deve começar com `v`) | `EZYSHIELD_VERSION=v0.3.0-rc.1` |
| `EZYSHIELD_BASE_URL` | Instalar a partir de um espelho customizado (sobrescreve seleção de versão) | `EZYSHIELD_BASE_URL=https://mirror.exemplo.com/ezyshield/v0.3.0` |

---

## Verificando a instalação

```bash
# Verificar se os binários estão no lugar
ezyshield version
ezyshield-enforcer --help

# Wizard de configuração interativa (requer root/sudo)
sudo ezyshield init
```

Se você vir informações de versão e texto de ajuda, a instalação foi bem-sucedida.
