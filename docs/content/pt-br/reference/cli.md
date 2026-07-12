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

### ezyshield config enforcer <name>

Wizard interativo para adicionar ou reconfigurar um enforcer em uma instalação existente — os mesmos prompts e a mesma validação seca de token do wizard de init, sem regenerar mais nada.

```bash
sudo ezyshield config enforcer cloudflare
```

- A escrita é atômica (arquivo temporário + rename); o arquivo anterior é mantido como `config.yaml.bak` e a configuração mesclada é revalidada antes de qualquer coisa tocar o disco. Comentários não são preservados — recupere-os do `.bak` se necessário.
- Tokens secretos vão para o arquivo `.env` ao lado do `config.yaml` (modo 0600), nunca para o `config.yaml` em si (`api_token: env:CLOUDFLARE_API_TOKEN`).
- Em caso de sucesso, o comando imprime as chaves alteradas e os próximos passos (`config validate`, reiniciar o daemon). Se o wizard for abortado, nada é escrito.

Nomes disponíveis: `cloudflare`. Os tipos `notifier`, `ai` e `collector` seguem o mesmo padrão e estão sendo adicionados componente a componente.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

[Traduções a seguir...]
