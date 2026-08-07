---
title: Instalação não-interativa (Ansible, cloud-init)
description: Provisione o EzyShield sem interação usando um arquivo de respostas
order: 6
---

# Instalação não-interativa (automação)

Por padrão, `ezyshield init` é um assistente interativo. Para Ansible,
cloud-init, Terraform, packer/imagens douradas, ou qualquer provisionamento
automatizado, rode-o em modo **não-interativo**: a mesma detecção de ambiente, a
mesma validação e exatamente a mesma configuração que o assistente gera — sem
TTY e sem perguntas.

```bash
ezyshield init --non-interactive --answers /etc/ezyshield/init.yaml
```

O `--non-interactive` (abreviado `-n`) é guiado por um **arquivo de respostas**
(`--answers`) e/ou um pequeno conjunto de **flags de sobrescrita**. Passar
`--answers` implica `--non-interactive`. O que ele faz:

- A detecção continua rodando (nftables, Docker, servidores web, unidade SSH).
  Suas respostas **fixam ou sobrescrevem** o resultado.
- Respostas ausentes ou inválidas produzem **um único erro listando todos os
  problemas de uma vez**, saída com código diferente de zero e **nada escrito** —
  uma execução que falha nunca deixa um `/etc/ezyshield` pela metade.
- A configuração gerada é **sempre `armed: false`** (dry-run). Você arma
  explicitamente, mais tarde, depois de observar uma saída de dry-run limpa.
- Reexecutar sobre uma configuração existente **recusa sem `--force`** (igual ao
  assistente).
- A configuração e a política são escritas de forma **atômica**.

> **Segredos nunca são passados como flags ou valores no arquivo de respostas.**
> Um valor em flag ou arquivo vaza no histórico do shell e na lista de
> processos. Você referencia o **NOME** de uma variável de ambiente; o valor real
> vai no `/etc/ezyshield/.env` (modo `0600`) ou numa credencial do systemd. Veja
> [Segredos](#segredos) abaixo.

## Referência do arquivo de respostas

O arquivo de respostas é um documento YAML. Ele espelha as perguntas do
assistente. **Toda chave é opcional** — omita uma seção para aceitar o
comportamento detectado/padrão. Chaves desconhecidas são rejeitadas (então um
erro de digitação falha ruidosamente em vez de não fazer nada).

```yaml
# ── Coletores: de onde o EzyShield lê os logs ──────────────────────────────
collectors:
  # Monitora SSH via journald usando a unidade detectada. Padrão: true.
  ssh: true

  # OPCIONAL. Quando presente, esta lista SUBSTITUI a autodetecção de
  # servidores web. Omita a chave `web:` inteira para aceitar todos os
  # servidores web detectados.
  web:
    - kind: file                        # file | docker
      path: /var/log/nginx/access.log   # obrigatório para kind: file
      parser: nginx                     # nginx | apache | apache-error | traefik | caddy
    - kind: docker
      container: my-nginx               # obrigatório para kind: docker
      parser: nginx

# ── Allowlist: IPs/CIDRs que NUNCA podem ser banidos (anti-lockout) ────────
allowlist:
  # Fortemente recomendado: seu(s) IP(s) de gerência. Omitir isto deixa
  # admin_cidrs vazio, e `ezyshield arm` vai sinalizar isso antes de armar.
  admin_ips: [203.0.113.4, 10.0.0.0/24]

# ── Análise por IA (opcional) ──────────────────────────────────────────────
ai:
  enabled: true
  provider: anthropic                   # anthropic | openai | ollama
  model: claude-haiku-4-5-20251001      # opcional; usa o padrão do provider quando omitido
  # NOME da variável de ambiente que guarda a chave — NÃO a chave em si.
  # Opcional; usa o nome canônico do provider (ANTHROPIC_API_KEY / OPENAI_API_KEY).
  api_key_env: ANTHROPIC_API_KEY

# ── Enforcement na borda: Cloudflare (opcional) ────────────────────────────
enforce:
  cloudflare:
    - name: main                        # obrigatório quando há mais de uma conta
      mode: lists                       # lists | rulesets (padrão: lists)
      account_id: 0123456789abcdef0123456789abcdef   # obrigatório no modo lists
      list_name: ezyshield_blocked      # opcional (modo lists)
      zone_ids: []                      # obrigatório para rulesets; opcional para lists
      action: block                     # block | challenge | js_challenge (padrão: block)
      # NOME da variável de ambiente que guarda o token. Opcional; derivado de
      # `name` quando omitido (CLOUDFLARE_API_TOKEN, ou CLOUDFLARE_API_TOKEN_<NOME>).
      api_token_env: CLOUDFLARE_API_TOKEN
```

O enforcement local via `nftables` é habilitado automaticamente quando o `nft` é
detectado no host; não há resposta para ele. Ao contrário do assistente
interativo, que oferece instalar um `nftables` ausente, o init não-interativo
**nunca executa um gerenciador de pacotes** — ele só escreve configuração. Num
host sem `nft` ele reporta a ausência e continua (dry-run e enforcement de borda
seguem funcionando); instale o `nftables` antes, como o play Ansible abaixo faz.

## Flags de sobrescrita

As flags sobrescrevem o valor correspondente do arquivo de respostas (uma flag
não definida nunca sobrescreve um valor do arquivo):

| Flag | Efeito |
|------|--------|
| `--non-interactive`, `-n` | Ativa o caminho automatizado |
| `--answers CAMINHO` | Lê as respostas de CAMINHO (implica `-n`) |
| `--force` | Sobrescreve um `config.yaml` / `policy.yaml` existente |
| `--config-dir DIR` | Escreve em DIR em vez de `/etc/ezyshield` (pula passos de sistema) |
| `--admin-ips "IP,CIDR"` | Sobrescreve `allowlist.admin_ips` |
| `--monitor-ssh` | Sobrescreve `collectors.ssh` |
| `--enable-ai` | Sobrescreve `ai.enabled` |
| `--ai-provider NOME` | Sobrescreve `ai.provider` |
| `--ai-model NOME` | Sobrescreve `ai.model` |
| `--ai-key-env NOME` | Sobrescreve `ai.api_key_env` (um **NOME** de variável, nunca uma chave) |
| `--json` | Emite o resumo como JSON no stdout (o progresso vai para o stderr) |

Uma execução só com flags nem precisa de arquivo de respostas:

```bash
ezyshield init -n --admin-ips "203.0.113.4" --enable-ai --ai-provider anthropic
```

## Segredos

O `config.yaml` gerado nunca contém um segredo — os campos de credencial são
escritos como referências `env:VARNAME`. Para cada variável referenciada, o init
escreve uma linha **placeholder** no `/etc/ezyshield/.env` (modo `0600`) para que
você tenha um lugar visível e o `EnvironmentFile=` do systemd nunca falhe:

```
ANTHROPIC_API_KEY=YOUR_API_KEY_HERE
CLOUDFLARE_API_TOKEN=YOUR_API_KEY_HERE
```

Sua automação substitui esses placeholders pelos valores reais do seu cofre de
segredos (Ansible Vault, sops, segredos do cloud-init, `LoadCredential=` do
systemd). Uma reexecução **preserva** qualquer valor real já presente — ela só
preenche o que estiver faltando.

## Ansible

```yaml
- name: Provisionar o EzyShield em dry-run
  hosts: webservers
  become: true
  tasks:
    - name: Garantir que o nftables está instalado (o init nunca instala pacotes)
      ansible.builtin.package:
        name: nftables
        state: present

    - name: Escrever o arquivo de respostas
      ansible.builtin.copy:
        dest: /etc/ezyshield/init.yaml
        mode: "0600"
        content: |
          collectors:
            ssh: true
          allowlist:
            admin_ips: ["{{ ansible_default_ipv4.address }}"]
          ai:
            enabled: true
            provider: anthropic
            api_key_env: ANTHROPIC_API_KEY

    - name: Rodar o init não-interativo
      ansible.builtin.command:
        cmd: ezyshield init --non-interactive --answers /etc/ezyshield/init.yaml
        creates: /etc/ezyshield/config.yaml   # idempotente: pula se já provisionado

    - name: Instalar a chave de API do Vault no .env
      ansible.builtin.lineinfile:
        path: /etc/ezyshield/.env
        regexp: '^ANTHROPIC_API_KEY='
        line: "ANTHROPIC_API_KEY={{ vault_anthropic_api_key }}"
        mode: "0600"
      no_log: true

    - name: Habilitar e iniciar os serviços (ainda em dry-run até você armar)
      ansible.builtin.systemd:
        name: "{{ item }}"
        enabled: true
        state: started
      loop:
        - ezyshield-enforcer
        - ezyshield
```

A guarda `creates:` e a própria recusa do init sem `--force` te dão duas camadas
independentes de idempotência: reexecutar o playbook não roda o init de novo nem
sobrescreve a configuração.

## cloud-init

```yaml
#cloud-config
write_files:
  - path: /etc/ezyshield/init.yaml
    permissions: "0600"
    content: |
      collectors:
        ssh: true
      allowlist:
        admin_ips: [203.0.113.4]
runcmd:
  - ezyshield init --non-interactive --answers /etc/ezyshield/init.yaml
  # Injete o segredo real a partir dos metadados da instância / cofre aqui,
  # e depois: systemctl enable --now ezyshield-enforcer ezyshield
```

## Verificando em CI

O `--json` fornece um resumo legível por máquina no qual você pode fazer
asserções num pipeline:

```bash
ezyshield init -n --config-dir ./out --json | jq -e '.armed == false'
```

```json
{
  "mode": "DRY-RUN (logging only, nothing blocked)",
  "armed": false,
  "config_dir": "/etc/ezyshield",
  "configured": ["collector: journald (SSH unit ssh)", "enforcer: nftables (/usr/sbin/nft)"],
  "skipped": ["AI analysis — disabled (rule engine only)"],
  "files": ["/etc/ezyshield/config.yaml", "/etc/ezyshield/policy.yaml (armed: false)"],
  "next_steps": ["ezyshield doctor — verify the configuration", "..."]
}
```

## Armando

O init não-interativo é sempre dry-run de propósito. Quando você tiver observado
uma saída limpa por um dia ou mais, arme explicitamente — pela sua automação ou
na mão:

```bash
ezyshield arm      # recusa se admin_cidrs estiver vazio; verifica o enforcement antes
```

Veja a [referência da CLI](../reference/cli.md) para `doctor`, `watch` e `arm`.
