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

> **Antes do v0.1.0 ser lançado:** toda release publicada é um release
> candidate, então os snippets abaixo usam a suite `testing` — a que
> funciona hoje. Quando o v0.1.0 sair, troque `testing` por `stable` nos
> dois para acompanhar só releases estáveis.

**Debian / Ubuntu:**

```bash
curl -fsSL https://packages.ezyshield.com/ezyshield.asc | sudo gpg --dearmor -o /usr/share/keyrings/ezyshield.gpg
echo "deb [signed-by=/usr/share/keyrings/ezyshield.gpg] https://packages.ezyshield.com/apt testing main" | sudo tee /etc/apt/sources.list.d/ezyshield.list
sudo apt update && sudo apt install ezyshield
```

**RHEL / Rocky / Alma:**

```bash
sudo tee /etc/yum.repos.d/ezyshield.repo <<'EOF'
[ezyshield]
name=EzyShield
baseurl=https://packages.ezyshield.com/rpm/testing/$basearch
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

Para trocar para o canal estável quando o v0.1.0 sair, troque `testing`
por `stable` em qualquer dos snippets. Os pacotes **não** habilitam nem
iniciam serviço algum — rode `sudo ezyshield init` depois de instalar.

---

## Completions de shell e páginas de manual

Completions (bash/zsh/fish) e páginas de manual são geradas diretamente da
árvore de comandos do `ezyshield` no momento do build, então elas sempre
batem exatamente com a superfície de CLI da versão instalada — sem
divergência em relação ao `--help`.

**Instalado via apt / dnf:** as duas coisas são instaladas automaticamente
pelo pacote, nada para configurar. As páginas de manual funcionam
imediatamente:

```bash
man ezyshield
man ezyshield-ban   # cada subcomando tem sua própria página, ex.: ezyshield-ban(1)
```

As completions de bash e zsh ficam ativas na próxima vez que você abrir um
shell (ou rodar `exec $SHELL`) — elas ficam nos diretórios padrão de
completion da distro (`/usr/share/bash-completion/completions/`,
`/usr/share/zsh/vendor-completions/`). O fish detecta
`/usr/share/fish/vendor_completions.d/ezyshield.fish` da mesma forma, sem
precisar de reload além de abrir um shell novo.

**Instalado via script ou binário/tarball bruto:** gere o script de
completion com o comando `completion` embutido e coloque-o onde seu shell
carrega completions:

```bash
# Bash (para todo o sistema)
ezyshield completion bash | sudo tee /etc/bash_completion.d/ezyshield > /dev/null

# Zsh (por usuário — garanta que o diretório de destino está no seu $fpath)
ezyshield completion zsh > "${fpath[1]}/_ezyshield"

# Fish
ezyshield completion fish > ~/.config/fish/completions/ezyshield.fish
```

Depois, recarregue seu shell (`exec $SHELL`). O tarball de release também
traz os mesmos arquivos pré-gerados em `completions/` e `man/`, caso você
prefira copiá-los diretamente em vez de rodar `ezyshield completion` você
mesmo.

---

## Instalando uma versão específica ou candidata a lançamento

Se você quer uma versão específica (incluindo candidatos a lançamento como
`v0.1.0-rc.N` — confira a [página de releases](https://github.com/evertramos/ezy-shield/releases)
para o tag atual), configure `EZYSHIELD_VERSION`:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0-rc.N sh
```

A versão deve começar com `v`. As versões disponíveis estão listadas em [github.com/evertramos/ezy-shield/releases](https://github.com/evertramos/ezy-shield/releases).

> **Antes do v0.1.0 ser lançado:** este é o método via install-script que
> funciona hoje — toda release publicada é um release candidate. Copie o
> tag exato da página de releases acima.

---

## Instalação rápida

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

Esse one-liner é **package-first**: em um host com `apt-get` ou `dnf`/`yum`
onde o repositório de pacotes está acessível, ele configura o mesmo
repositório mostrado acima (chave GPG + entrada de source) e instala via
gerenciador de pacotes — resultado idêntico a seguir os passos de apt/dnf
manualmente. Os binários crus em `/usr/local/bin/` só são usados quando:

- o host não tem `apt-get`/`dnf`/`yum` algum,
- `EZYSHIELD_BASE_URL` aponta para um espelho customizado (instalação air-gapped), ou
- a configuração do repositório ou a checagem de acessibilidade falha — o
  script imprime um aviso e cai para o modo binário automaticamente, então a
  instalação ainda é concluída.

Uma exceção: se o host **já roda uma instalação de EzyShield gerenciada por
pacote**, todo caminho de modo binário se recusa em vez de instalar
(binários crus em `/usr/local/bin` esconderiam os do pacote em `/usr/bin`)
— atualize com `apt`/`dnf` nesse caso, ou defina `EZYSHIELD_FORCE_SCRIPT=1`
para sobrepor com um aviso ruidoso.

Você pode forçar qualquer um dos dois caminhos explicitamente com `EZYSHIELD_METHOD`:

```bash
# Sempre instalar via pacotes (falha ruidosamente se não for possível)
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=packages sh

# Sempre instalar binários crus, mesmo com um gerenciador de pacotes presente
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=binary sh
```

Se o script encontrar uma instalação via script anterior (binários em
`/usr/local/bin`, units em `/etc/systemd/system`) ao rotear para uma
instalação via pacote, ele imprime os comandos exatos de limpeza para que o
novo pacote não fique escondido atrás da instalação antiga — veja
[Migrando da instalação via script para pacotes](#migrando-da-instalação-via-script-para-pacotes)
abaixo.

> **Antes do v0.1.0 ser lançado:** quando nenhum dos dois métodos de
> instalação resolve uma release estável, o comando acima imprime
> instruções de instalação em vez de instalar (veja o repositório de
> pacotes `testing` mais acima) — nenhuma flag será necessária assim que o
> v0.1.0 sair.

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

**Instalado via script** (binários em `/usr/local/bin`) — rode o script de
novo. Em um host com `apt-get`/`dnf` disponível agora, o script é
package-first por padrão (veja [Instalação rápida](#instalação-rápida)) e vai
oferecer migrar você para pacotes em vez de só substituir os binários — veja
a próxima seção. Para continuar atualizando em modo binário explicitamente:

```bash
# Última versão estável, permanecendo na instalação via binário
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=binary sh

# Ou versão específica (confira a página de releases para o tag atual,
# ex. v0.1.0-rc.N antes do v0.1.0 sair)
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=binary EZYSHIELD_VERSION=v0.1.0-rc.N sh

sudo systemctl restart ezyshield-enforcer ezyshield
```

---

## Migrando da instalação via script para pacotes

Um host instalado primeiro via script (binários em `/usr/local/bin`, units em
`/etc/systemd/system`) que depois recebe `apt install`/`dnf install`
ezyshield pode acabar rodando silenciosamente a build **antiga** em tudo:
`/usr/local/bin` vem antes de `/usr/bin` no `PATH`, e os arquivos de unit em
`/etc/systemd/system` têm precedência sobre as units do pacote em
`/usr/lib/systemd/system` — o gerenciador de pacotes reporta a versão nova
instalada, mas o binário e o serviço que realmente rodam são os antigos.

Duas formas de corrigir ou evitar isso:

**Deixe o get.sh fazer isso.** Rodar o one-liner de novo em um host com
`apt-get`/`dnf` roteia para a instalação via pacote por padrão (veja
[Instalação rápida](#instalação-rápida)) e detecta uma instalação via script
que esteja escondendo o pacote automaticamente, imprimindo os comandos
exatos de limpeza:

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

Ele só executa a limpeza quando você opta por isso — passe
`EZYSHIELD_CLEANUP=1` para uma execução não interativa, ou responda ao
prompt interativo:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_CLEANUP=1 sh
```

**Ou limpe manualmente** (os mesmos comandos que o script imprime):

```bash
sudo systemctl stop ezyshield ezyshield-enforcer
sudo rm -f /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer
sudo rm -f /etc/systemd/system/ezyshield.service /etc/systemd/system/ezyshield-enforcer.service
sudo systemctl daemon-reload
sudo systemctl enable --now ezyshield-enforcer ezyshield
```

De qualquer forma, rode `ezyshield doctor` depois — ele FAIL ruidosamente se
uma instalação via script ainda estiver escondendo o pacote (binário
presente em mais de um local do `PATH` com conteúdo diferente, ou uma
override de unit em `/etc/systemd/system` cujo `ExecStart` ainda aponta para
`/usr/local/bin`), e a dica que ele imprime repete os comandos exatos de
limpeza acima.

---

## Desinstalando

**Instalado via apt / dnf:**

```bash
# Debian / Ubuntu
sudo apt remove ezyshield

# RHEL / Rocky / Alma
sudo dnf remove ezyshield

# Também remover configuração (se desejado)
sudo rm -rf /etc/ezyshield
```

**Instalado via script** — o próprio `get.sh` remove exatamente os arquivos
que ele instalou (binários em `/usr/local/bin`, units em
`/etc/systemd/system`) e nunca toca em arquivos gerenciados pelo pacote:

```bash
curl -sfL https://get.ezyshield.com | sudo sh -s -- --uninstall
# equivalente: curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_UNINSTALL=1 sh

# Também remover configuração (se desejado)
sudo rm -rf /etc/ezyshield
```

---

## Referência de variáveis de ambiente

| Variável | Propósito | Exemplo |
|----------|-----------|---------|
| `EZYSHIELD_METHOD` | `auto` (padrão), `packages`, ou `binary` — força o método de instalação em vez de auto-detectar | `EZYSHIELD_METHOD=binary` |
| `EZYSHIELD_VERSION` | Instalar uma versão específica (deve começar com `v`). Só no modo binário | `EZYSHIELD_VERSION=v0.1.0-rc.N` |
| `EZYSHIELD_BASE_URL` | Instalar a partir de um espelho customizado (sobrescreve seleção de versão, força modo binário) | `EZYSHIELD_BASE_URL=https://mirror.exemplo.com/ezyshield/v0.1.0` |
| `EZYSHIELD_API_BASE_URL` | Sobrescreve a base da API do GitHub usada para resolver metadados de release (espelhos privados de API, testes) | `EZYSHIELD_API_BASE_URL=https://api.mirror.exemplo.com` |
| `EZYSHIELD_PACKAGES_BASE_URL` | Sobrescreve a base do repositório de pacotes usada na configuração do repo e na checagem de acessibilidade (espelhos privados, testes) | `EZYSHIELD_PACKAGES_BASE_URL=https://packages.mirror.exemplo.com` |
| `EZYSHIELD_CLEANUP` | Defina como `1` para remover uma instalação via script que esteja escondendo o pacote, sem interação, ao rotear para uma instalação via pacote | `EZYSHIELD_CLEANUP=1` |
| `EZYSHIELD_UNINSTALL` | Defina como `1` (equivalente a `--uninstall`) para remover os artefatos da instalação via script e sair | `EZYSHIELD_UNINSTALL=1` |
| `EZYSHIELD_FORCE_SCRIPT` | Defina como `1` para forçar uma instalação via binário em um host que já tem uma instalação gerenciada por pacote — por padrão todo caminho de modo binário se recusa nesse caso, porque binários em `/usr/local/bin` esconderiam os do pacote | `EZYSHIELD_FORCE_SCRIPT=1` |

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
