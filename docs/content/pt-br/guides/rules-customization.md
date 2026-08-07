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
