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

Nomes disponíveis: `cloudflare`. Os tipos `notifier` e `collector` seguem o mesmo padrão e estão sendo adicionados componente a componente.

Códigos de saída: `0` salvo, `1` wizard abortado ou falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

### ezyshield config ai <provider>

Wizard interativo para configurar (ou trocar) o provedor de IA em uma instalação existente — os mesmos prompts de modelo e chave de API do wizard de init, sem regenerar mais nada.

```bash
sudo ezyshield config ai anthropic
sudo ezyshield config ai openai
sudo ezyshield config ai ollama
```

- A chave de API é lida com entrada oculta e oferecida de duas formas: colar a chave (armazenada no arquivo `.env` ao lado do `config.yaml`, modo 0600, mesclada sem tocar nas outras linhas) ou referenciar uma variável de ambiente que você já gerencia (ex.: via sops/vault) — nesse caso o wizard grava `api_key: env:SUA_VAR` e nunca toca o `.env`. Chaves nunca vão para o `config.yaml`.
- Pressionar ENTER no prompt de colagem é aceitável: uma chave existente no `.env` é mantida como está; caso contrário, um placeholder é gravado para você preencher depois. `ollama` roda localmente e não tem chave.
- Reconfigurar substitui os campos do provedor (`provider`, `model`, `api_key`) mas preserva seus ajustes (`ambiguous_band`, `token_budget_daily`). A semântica de escrita é a mesma do `config enforcer`: escrita atômica, `config.yaml.bak`, revalidação antes de salvar.

Provedores disponíveis: `anthropic`, `openai`, `ollama`.

Códigos de saída: `0` salvo, `1` falha de escrita, `2` config.yaml não encontrado (execute `init` primeiro).

[Traduções a seguir...]
