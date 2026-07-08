# Instalando EzyShield

Este guia cobre todas as formas de instalar EzyShield: a partir de uma versão pré-compilada, uma versão específica ou candidata a lançamento, um espelho customizado, ou a partir do código-fonte.

---

## Instalação rápida (última versão estável)

```bash
curl -sfL https://get.ezyshield.com | sh
```

Isso faz download da última versão estável, verifica checksums e instala os binários em `/usr/local/bin/`.

---

## Instalando uma versão específica ou candidata a lançamento

Se você quer uma versão específica (incluindo candidatos a lançamento como `v0.3.0-rc.1`), configure `EZYSHIELD_VERSION`:

```bash
curl -sfL https://get.ezyshield.com | EZYSHIELD_VERSION=v0.3.0-rc.1 sh
```

A versão deve começar com `v`. As versões disponíveis estão listadas em [github.com/evertramos/ezy-shield/releases](https://github.com/evertramos/ezy-shield/releases).

---

## Instalando a partir de um espelho customizado (ambientes isolados)

Para instalações em ambientes isolados ou CI, aponte o instalador para um espelho customizado com ambos os binários e `checksums.txt`:

```bash
curl -sfL https://get.ezyshield.com | EZYSHIELD_BASE_URL=https://mirror.interno.com/ezyshield/v0.3.0 sh
```

O script irá:
1. Fazer download de `checksums.txt`, `ezyshield-linux-amd64` e `ezyshield-enforcer-linux-amd64` (ou arquitetura apropriada)
2. Verificar checksums SHA-256
3. Instalar em `/usr/local/bin/`

**Nota de segurança:** Checksums protegem contra corrupção na transferência, mas NÃO autenticam um espelho comprometido. Use isso apenas para espelhos confiáveis ou artefatos que você já tenha validado.

Ao usar `EZYSHIELD_BASE_URL`, você também pode configurar `EZYSHIELD_VERSION` para sua própria versão:

```bash
EZYSHIELD_VERSION=internal-rc1 EZYSHIELD_BASE_URL=https://mirror.interno.com/ezyshield/v0.3.0 sh
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

Para atualizar uma instalação existente:

```bash
# Desinstalar
sudo rm /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer

# Reinstalar (última versão)
curl -sfL https://get.ezyshield.com | sh

# Ou versão específica
curl -sfL https://get.ezyshield.com | EZYSHIELD_VERSION=v0.4.0 sh
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
| `EZYSHIELD_BASE_URL` | Instalar a partir de um espelho customizado (sobrescreve seleção de versão) | `EZYSHIELD_BASE_URL=https://mirror.interno.com/ezyshield/v0.3.0` |

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
