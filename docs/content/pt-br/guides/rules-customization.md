---
title: Customizando Regras de Detecção
description: Ajuste ou adicione regras com drop-ins em rules.d que sobrevivem a updates
order: 5
---

# Customizando Regras de Detecção

As regras de detecção do EzyShield vêm **embutidas no binário** — toda
instalação roda o conjunto completo e atual sem nenhum arquivo em disco, e
todo `ezyshield update` entrega o tuning de regras mais recente
automaticamente.

Para ajustar uma regra (ou adicionar a sua) você não faz fork dessa base:
você coloca um arquivo em `/etc/ezyshield/rules.d/`.

## Como os drop-ins funcionam

- Todo arquivo `*.yaml` em `rules.d/` é carregado em **ordem léxica**
  (`10-wordpress.yaml` antes de `50-local.yaml`).
- As entradas fazem merge sobre as regras embutidas **por `name`**: uma
  entrada com o mesmo nome de uma regra embutida **a substitui**; um nome
  novo **adiciona** uma regra. Arquivos posteriores vencem os anteriores.
- Tudo que você *não* sobrescrever continua recebendo updates do binário —
  você ajusta um threshold, e as demais regras ficam atuais para sempre.
- Sobrescrever uma regra embutida gera um **WARN** no startup
  (deliberadamente barulhento: um drop-in que enfraquece uma regra de
  proteção deve ser visível).
- Um drop-in inválido **impede o daemon de iniciar** (fail-closed) — um
  typo nunca degrada a detecção silenciosamente. Depois de editar,
  reinicie e confira: `sudo systemctl restart ezyshield && sudo systemctl status ezyshield`.

## Exemplo: aumentar o threshold do wp-login

```yaml
# /etc/ezyshield/rules.d/50-local.yaml
rules:
  - name: http_wp_probe        # mesmo name da embutida => override
    description: "WordPress login probe (site-tuned)"
    kinds: [http_request]
    field: path
    contains: wp-login
    window: 60s
    threshold: 10              # o default embutido é 3
    score: 80
    category: scanner
```

## Exemplo: adicionar a sua própria regra

```yaml
# /etc/ezyshield/rules.d/60-admin-panel.yaml
rules:
  - name: local_admin_probe    # name novo => adicionada junto às embutidas
    description: "Probing our internal admin path"
    kinds: [http_request]
    field: path
    contains: /internal-admin
    window: 60s
    threshold: 3
    score: 85
    category: scanner
```

O schema das regras (campos, matchers, windows) está documentado no
[Getting Started §6](../getting-started/index.md); o conjunto completo
atual é distribuído como `/etc/ezyshield/rules.yaml.example` para
referência.

## Teste uma regra antes de habilitá-la

Escrever uma regra às cegas — habilitar e esperar — é assim que falsos
positivos entram em produção. O `rule test` avalia uma regra a seco contra
o histórico de eventos que o daemon já guarda, com **zero efeitos
colaterais** (sem strikes, sem bans, sem escrita de auditoria; o daemon nem
precisa estar rodando):

```console
$ ezyshield rule test ssh_bruteforce_daily --since 7d
Rule test: ssh_bruteforce_daily
  kinds: ssh_fail, ssh_invalid_user | window: 24h0m0s | threshold: 5 | ...

  Would have fired : 12 time(s)
  Unique IPs       : 4
  Allowlisted hits : 1 — this rule would fire on protected addresses; tune it before enabling
```

O argumento é o nome de uma regra carregada (embutida ou drop-in) ou o
caminho de um arquivo YAML avulso — dá para testar o
`rules.d/60-admin-panel.yaml` *antes* de copiá-lo para o lugar. A regra
passa primeiro pela mesma validação fail-closed do loader do daemon; uma
regra inválida é um erro claro e exit não-zero.

A linha de **allowlisted hits** é o alerta antecipado de falso positivo:
conta as detecções que cairiam em endereços cobertos pelo seu
`allowlist`/`admin_cidrs` ou pela allowlist de runtime. Uma regra que
dispara nas suas próprias faixas precisa de tuning, não de habilitação.
`--json` entrega o resultado completo para scripts.

Limitação honesta: a avaliação usa os agregados horários armazenados, então
a granularidade é limitada pelos buckets de 1 hora e pela retenção — e só
kinds referenciados por regras de janela longa (>1h) são persistidos.
Matchers de campo (`field`/`value`/`contains`) não se aplicam a contagens,
então essas regras são reportadas como um **teto** (upper bound) em nível
de kind, marcado de forma bem visível.

## Instalações WordPress

Quando o `ezyshield init` detecta containers WordPress, ele grava um
**template de tuning totalmente comentado** em `rules.d/10-wordpress.yaml`.
As regras de WordPress são embutidas e já estão ativas — o template existe
para que as regras mais ajustadas estejam a um descomentar de distância.
Rodar o `init` de novo nunca sobrescreve suas edições.

## Legado: `rules_path` (deprecated)

Definir `rules_path` no `config.yaml` substitui as regras embutidas pelo
seu arquivo **por inteiro** — sem merge, e o `rules.d/` é ignorado. Isso
congela a instalação fora de todo tuning de regras do upstream (updates
trocam o binário, nunca o seu arquivo), então o daemon loga um aviso no
startup quando está definido. Prefira drop-ins; para migrar, mova apenas
as suas *mudanças reais* para um `rules.d/50-local.yaml` e remova
`rules_path` do `config.yaml`.

## Fronteira de segurança

Regras — embutidas ou drop-in — apenas *sugerem* verdicts. As checagens de
allowlist e anti-lockout rodam depois, no decision engine, sobre todo alvo,
independentemente de qual regra disparou. Nenhuma regra pode allowlistar,
desbanir ou contornar essas garantias.
