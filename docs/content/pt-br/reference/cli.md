---
title: Referência de CLI
description: Todos os comandos e flags
order: 4
---

# Referência de CLI

[Conteúdo de tradução em andamento - veja docs/content/en/reference/cli.md para a versão em inglês]

Referência completa para a CLI do `ezyshield`.

## ezyshield config

Inspecionar e validar a configuração.

### ezyshield config show

Renderiza a configuração efetiva — após parsing, validação estrita e defaults — em YAML, ou JSON com `--json`. Valores de segredos nunca aparecem na saída: campos de credencial guardam referências `env:VARNAME` por design, e valores de headers de webhook (que podem conter tokens crus) são exibidos como `<redacted>`.

```bash
ezyshield config show

# Saída em JSON
ezyshield config show --json

# Arquivos em locais não padrão
ezyshield config show --config ./config.yaml --policy ./policy.yaml
```

Códigos de saída: `0` renderizado, `1` configuração inválida, `2` arquivo não encontrado / ilegível.

### ezyshield config validate

Valida `config.yaml` e `policy.yaml` sem iniciar o daemon: parsing YAML estrito, restrições de campos, monotonicidade da tabela de strikes, CIDRs da allowlist e avisos para caminhos de log ilegíveis ou variáveis de ambiente não definidas.

```bash
ezyshield config validate

# Arquivos em locais não padrão
ezyshield config validate --config ./config.yaml --policy ./policy.yaml
```

O comando de nível superior `ezyshield validate` é mantido como alias e se comporta de forma idêntica.

Códigos de saída: `0` válido (pode ter avisos), `1` erros encontrados, `2` arquivo não encontrado / ilegível.

[Traduções a seguir...]
